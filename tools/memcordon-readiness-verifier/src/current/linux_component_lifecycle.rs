//! Independent joins for actual current controller boundary experiments.
use super::CaseEvidenceV2;
use crate::{ComponentBuild, VerificationResult};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

pub(super) const JOURNAL_FIELDS: &[&str] = &[
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

pub(super) fn verify_observations(
    evidence: &CaseEvidenceV2,
    facet: &str,
    source_commit: &str,
    target: &str,
    version: &str,
    captures: &BTreeMap<String, String>,
    resolve: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    let scenario = facet;
    let mut expected: BTreeSet<&str> = [
        "entrypoint.bin",
        "runtime-snapshot.json",
        "input-snapshot.json",
        "request.json",
        "attempt.json",
        "prepared.json",
        "start.json",
        "journal-before.json",
        "held-before.json",
        "cgroup-before.json",
        "allocations-before.json",
        "allocations-after.json",
        "operands.json",
        "provider-manifest.json",
        "action.json",
        "stdout.bin",
        "stderr.bin",
        "frontend-wait.json",
        "journal-after.json",
        "acknowledgment-process.json",
    ]
    .into_iter()
    .collect();
    if scenario != "journal-barrier" {
        expected.extend([
            "prepared-ack.json",
            "released-stdout.bin",
            "journal-released.json",
        ]);
    }
    if scenario == "release-barrier" {
        expected.insert("result.json");
    } else {
        expected.extend(["recovery.json", "recovery-process.json"]);
        if evidence.raw_result.is_some() {
            expected.insert("result.json");
        }
    }
    if scenario == "repeated-recovery" {
        expected.extend(["recovery-repeat.json", "recovery-repeat-process.json"]);
    }
    if captures.keys().map(String::as_str).collect::<BTreeSet<_>>() != expected {
        return Err("native lifecycle raw capture inventory differs".into());
    }
    let raw = |name: &str| -> VerificationResult<Vec<u8>> {
        resolve(
            captures
                .get(name)
                .ok_or_else(|| format!("actual native lifecycle capture absent: {name}"))?,
        )
    };
    let document = |name: &str| -> VerificationResult<Value> { crate::wire::decode(&raw(name)?) };
    let request = document("request.json")?;
    let digest = super::linux::request_digest(&raw("request.json")?)?;
    let association = document("attempt.json")?;
    closed(
        &association,
        &[
            "format",
            "revision",
            "attempt",
            "challenge",
            "request_sha256",
            "boot_id",
            "provider",
            "control",
        ],
    )?;
    for name in ["attempt", "challenge"] {
        let bytes: Vec<u8> =
            serde_json::from_value(association[name].clone()).map_err(|e| e.to_string())?;
        if bytes.len() != 16 || bytes.iter().all(|byte| *byte == 0) {
            return Err("original provider attempt/challenge absent".into());
        }
    }
    if association["format"] != "memcordon.workload-attempt"
        || association["revision"] != 1
        || association["request_sha256"] != digest
        || association["boot_id"].as_str().is_none_or(str::is_empty)
        || association["provider"]["source_commit"] != source_commit
    {
        return Err("original attempt/provider/request differs".into());
    }
    let prepared_bytes = raw("prepared.json")?;
    let prepared = document("prepared.json")?;
    closed(
        &prepared,
        &["format", "revision", "association", "request", "native"],
    )?;
    let native = &prepared["native"];
    closed(
        native,
        &[
            "caller_namespaces",
            "user_namespace",
            "boot_id",
            "caller",
            "target",
            "target_namespace_pid",
            "namespace_init",
            "guardian",
            "caller_uid",
            "target_uid",
            "target_gid",
            "cgroup_device",
            "cgroup_inode",
            "init_uid",
            "init_nondumpable",
            "mount_namespace",
            "pid_namespace",
            "network_namespace",
            "ipc_namespace",
            "root_device",
            "root_inode",
            "filter_abi",
            "filter_instruction_sha256",
            "entrypoint_sha256",
            "supplementary_groups",
            "no_new_privileges",
            "capabilities_empty",
            "exec_observed",
            "release_monotonic_millis",
            "exec_observed_monotonic_millis",
            "native_wait_status",
            "memory_oom_kill_count",
            "memory_oom_event_count",
            "memory_max_bytes",
        ],
    )?;
    if prepared["format"] != "memcordon.linux-workload-prepared"
        || prepared["revision"] != 1
        || prepared["association"] != association
        || prepared["request"]["request_sha256"] != digest
        || prepared["request"]["runtime_sha256"] != request["runtime"]["inputs"]["runtime_digest"]
        || prepared["request"]["input_sha256"] != request["runtime"]["inputs"]["input_digest"]
        || native["exec_observed"] != false
        || !native["release_monotonic_millis"].is_null()
        || !native["exec_observed_monotonic_millis"].is_null()
        || !native["native_wait_status"].is_null()
        || native["boot_id"] != association["boot_id"]
        || native["target_namespace_pid"]
            .as_u64()
            .is_none_or(|pid| pid == 0)
    {
        return Err(
            "actual prepared barrier was released, substituted or lacks original input binding"
                .into(),
        );
    }
    let snapshot_bytes = raw("runtime-snapshot.json")?;
    let snapshot: Value = crate::wire::decode(&snapshot_bytes)?;
    let entrypoint = crate::sha256(&raw("entrypoint.bin")?);
    if native["entrypoint_sha256"] != entrypoint
        || snapshot["format"] != "memcordon.workload-snapshot"
        || snapshot["revision"] != 1
        || snapshot["target"] != target
        || crate::sha256(&snapshot_bytes) != request["runtime"]["inputs"]["runtime_digest"]
        || !snapshot["entries"].as_array().is_some_and(|entries| {
            entries.iter().any(|entry| {
                entry["kind"] == "regular"
                    && entry["path"] == "bin/owned-readiness"
                    && entry["sha256"] == entrypoint
                    && entry["executable"] == true
            })
        })
    {
        return Err("actual prepared ELF differs from the original streamed runtime and retained fixture bytes".into());
    }
    let operands = document("operands.json")?;
    let memory = operands["memory_bytes"]
        .as_u64()
        .ok_or("original native memory operand absent")?;
    validate_snapshot_budget(
        &document("runtime-snapshot.json")?,
        &document("input-snapshot.json")?,
        memory,
        128 * 1024 * 1024,
    )?;
    if native["memory_max_bytes"] != memory {
        return Err(
            "actual native memory.max differs from the original snapshot-aware budget".into(),
        );
    }
    if document("input-snapshot.json")?["format"] != "memcordon.workload-snapshot"
        || crate::sha256(&raw("input-snapshot.json")?)
            != request["runtime"]["inputs"]["input_digest"]
        || operands["deadline_millis"] != 30000
        || operands["lifetime"] != "command"
        || !operands["working_directory"].is_null()
    {
        return Err("native boundary experiment budgets/lifetime changed".into());
    }
    super::linux_wire::verify_start(
        &raw("start.json")?,
        &request,
        &prepared["request"],
        &operands,
    )?;
    let action = document("action.json")?;
    closed(
        &action,
        &[
            "format",
            "revision",
            "scenario",
            "frontend",
            "association",
            "challenge",
            "prepared_ack",
            "signal",
            "victim",
            "native_signal_result",
            "released_stdout",
            "retired",
            "prepared_journal_phase",
            "service",
        ],
    )?;
    let challenge = action["challenge"]
        .as_str()
        .ok_or("actual workload challenge absent")?;
    crate::digest(challenge)?;
    let expected_args = vec![
        b"exec-held".to_vec(),
        challenge.as_bytes().to_vec(),
        b"/bin/owned-readiness".to_vec(),
        b"binary-file".to_vec(),
        challenge.as_bytes().to_vec(),
    ];
    if operands["target_argv"]
        != serde_json::to_value(crate::NativeArguments::UnixBytes(expected_args))
            .map_err(|e| e.to_string())?
    {
        return Err("native actor selected different target operands".into());
    }
    let manifest = document("provider-manifest.json")?;
    closed(
        &manifest,
        &[
            "format",
            "revision",
            "project",
            "version",
            "source_commit",
            "target",
            "components",
            "sealed",
        ],
    )?;
    if manifest["project"] != "memcordon"
        || manifest["sealed"]
            != json!({"selection":"included","agent_component":"sealed-agent","native_protocols":{"platform":"linux","provider_contract":3,"launch_wire":5},"mechanism":"linux-private-workload-v1","workload_request":{"format":"memcordon.workload-request","revision":1},"result":{"format":"memcordon.result","revision":3},"profile":"linux-private-workload-v1","profile_revision":1})
    {
        return Err(
            "native component manifest substitutes another profile/interface or authority layer"
                .into(),
        );
    }
    closed(
        &association["provider"],
        &["generation", "source_commit", "runtime_manifest_sha256"],
    )?;
    if association["provider"]["generation"] != format!("{version}:{}", source_commit) {
        return Err("native provider generation differs from exact selected source".into());
    }
    if manifest["format"] != "memcordon.runtime-manifest"
        || manifest["revision"] != 2
        || manifest["source_commit"] != source_commit
        || manifest["version"] != version
        || manifest["target"] != target
        || association["provider"]["runtime_manifest_sha256"]
            != crate::sha256(&raw("provider-manifest.json")?)
    {
        return Err("current installed provider manifest/source differs".into());
    }
    let before = document("journal-before.json")?;
    let journal_fields = JOURNAL_FIELDS;
    closed(&before, journal_fields)?;
    let attempt: Vec<u8> = serde_json::from_value(association["attempt"].clone())
        .map_err(|error| error.to_string())?;
    let attempt_name = hex::encode(attempt);
    if before["format"] != "memcordon.private-workload-journal"
        || before["revision"] != 1
        || before["attempt_id"] != attempt_name
        || before["boot_id"] != association["boot_id"]
        || before["request_sha256"] != digest
        || !before["outcome"].is_null()
        || !before["terminal"].is_null()
    {
        return Err("actual prepared journal format/attempt/outcome differs".into());
    }
    let cgroup = document("cgroup-before.json")?;
    closed(&cgroup, &["path", "device", "inode"])?;
    if cgroup["path"] != format!("/sys/fs/cgroup/memcordon-sealed/{attempt_name}")
        || cgroup["device"] != native["cgroup_device"]
        || cgroup["inode"] != native["cgroup_inode"]
        || before["cgroup"]["device"] != cgroup["device"]
        || before["cgroup"]["inode"] != cgroup["inode"]
    {
        return Err(
            "original actual cgroup kernel identity differs from durable/prepared owner".into(),
        );
    }
    let allocations = document("allocations-before.json")?;
    let allocations = allocations
        .as_array()
        .ok_or("actual native allocation queries absent")?;
    if allocations.len() != 3 {
        return Err("native allocation query inventory differs".into());
    }
    for (index, (role, path, field)) in [
        (
            "input-staging",
            format!("/var/lib/memcordon/workload-inputs/{attempt_name}"),
            "input_staging",
        ),
        (
            "root-staging",
            format!("/run/memcordon/private-root-{attempt_name}"),
            "staging",
        ),
    ]
    .into_iter()
    .enumerate()
    {
        let observed = &allocations[index];
        closed(observed, &["role", "path", "device", "inode"])?;
        if observed["role"] != role
            || observed["path"] != path
            || observed["device"] != before[field]["device"]
            || observed["inode"] != before[field]["inode"]
            || positive(&observed["inode"])? == 0
        {
            return Err(
                "actual native input/root staging identity differs from durable original intent"
                    .into(),
            );
        }
    }
    closed(
        &allocations[2],
        &["role", "path", "device", "inode", "bytes"],
    )?;
    let charge: Vec<u8> = serde_json::from_value(allocations[2]["bytes"].clone())
        .map_err(|error| error.to_string())?;
    if allocations[2]["role"] != "footprint"
        || allocations[2]["path"] != format!("/var/lib/memcordon/workload-resources/{attempt_name}")
        || charge.len() != 8
        || u64::from_be_bytes(charge.try_into().map_err(|_| "native footprint width")?) == 0
    {
        return Err("actual durable original native footprint charge absent".into());
    }
    let expected_absence = json!([
        {"path":format!("/sys/fs/cgroup/memcordon-sealed/{attempt_name}"),"absent":true},
        {"path":format!("/var/lib/memcordon/workload-inputs/{attempt_name}"),"absent":true},
        {"path":format!("/run/memcordon/private-root-{attempt_name}"),"absent":true},
        {"path":format!("/var/lib/memcordon/workload-resources/{attempt_name}"),"absent":true}]);
    if document("allocations-after.json")? != expected_absence {
        return Err("actual original native allocation paths were not retired".into());
    }
    let held = document("held-before.json")?;
    if before["association"] != association
        || before["request"] != prepared["request"]
        || before["native"] != *native
        || before["release"] != "not-released"
        || held["format"] != "memcordon.linux-current-held"
        || held["revision"] != 1
        || held["association"] != association
        || held["native"] != *native
        || held["journal_sha256"] != crate::sha256(&raw("journal-before.json")?)
        || held["root"]["device"] != native["root_device"]
        || held["root"]["inode"] != native["root_inode"]
    {
        return Err("prepared family/root differs from actual protected durable journal and independent kernel query".into());
    }
    for name in [
        "cgroup",
        "input_staging",
        "root_staging",
        "footprint",
        "guardian",
        "namespace_init",
        "target",
    ] {
        if before["intents"][name] != true {
            return Err("durable native acquisition intent missing before prepared release".into());
        }
    }
    let processes = held["processes"]
        .as_array()
        .ok_or("held native process queries absent")?;
    let retired = action["retired"]
        .as_array()
        .ok_or("held native retirement queries absent")?;
    let roles = ["worker", "control", "guardian", "namespace_init", "target"];
    if processes.len() != roles.len() || retired.len() != roles.len() {
        return Err("actual native process inventory incomplete".into());
    }
    let mut identities = BTreeSet::new();
    for ((process, retirement), role) in processes.iter().zip(retired).zip(roles) {
        let pid = positive(&process["snapshot"]["process_id"])?;
        let birth = positive(&process["snapshot"]["birth"])?;
        if process["role"] != role
            || !identities.insert((pid, birth))
            || before[role]["pid"] != pid
            || before[role]["start_time"] != birth
            || retirement["pid"] != pid
            || retirement["birth"] != birth
            || retirement["pidfd_readable"] != true
        {
            return Err("actual original held process identity/retirement differs".into());
        }
        if ["guardian", "namespace_init", "target"].contains(&role)
            && (native[role]["pid"] != pid || native[role]["birth"] != birth)
        {
            return Err("prepared native identity differs from held original process".into());
        }
    }
    let target = &processes[4];
    for (field, native_field) in [("uid", "target_uid"), ("gid", "target_gid")] {
        let values = target["credentials"][field]
            .as_array()
            .ok_or("actual target credentials absent")?;
        if values.len() != 4
            || values.iter().any(|v| v != &native[native_field])
            || native[native_field] == 0
        {
            return Err("native target fixed credential columns differ".into());
        }
    }
    if target["credentials"]["groups"] != json!([])
        || target["credentials"]["cap_effective"] != 0
        || target["credentials"]["cap_permitted"] != 0
        || target["credentials"]["cap_ambient"] != 0
        || target["credentials"]["no_new_privileges"] != 1
    {
        return Err("actual native target credential boundary differs".into());
    }
    if before["frontend"]["pid"] != action["frontend"]["pid"]
        || before["frontend"]["start_time"] != action["frontend"]["birth"]
        || before["control"]["pid"] != association["control"]["pid"]
        || before["control"]["start_time"] != association["control"]["birth"]
        || action["format"] != "memcordon.current-native-component-action"
        || action["revision"] != 1
        || action["scenario"] != evidence.key.scenario
        || action["association"] != association
    {
        return Err("actual original frontend/control/intervention association differs".into());
    }
    if scenario == "released-service-loss" {
        let service = &action["service"];
        closed(
            service,
            &[
                "unit",
                "query_status",
                "query_stdout",
                "query_stderr",
                "process",
                "image",
                "pidfd_readable",
            ],
        )?;
        closed(&service["process"], &["pid", "birth"])?;
        closed(&service["image"], &["device", "inode", "length", "sha256"])?;
        let query: Vec<u8> = serde_json::from_value(service["query_stdout"].clone())
            .map_err(|error| error.to_string())?;
        let pid: u64 = std::str::from_utf8(&query)
            .map_err(|error| error.to_string())?
            .trim()
            .parse()
            .map_err(|_| "actual service query PID invalid")?;
        if service["unit"] != "memcordon-sealed-agent.service"
            || service["query_status"] != 0
            || pid <= 1
            || service["process"]["pid"] != pid
            || service["process"]["birth"]
                .as_u64()
                .is_none_or(|birth| birth == 0)
            || service["pidfd_readable"] != true
            || !manifest["components"].as_array().is_some_and(|components| {
                components.iter().any(|component| {
                    component["id"] == "sealed-agent"
                        && component["sha256"] == service["image"]["sha256"]
                })
            })
        {
            return Err(
                "service loss did not kill and observe the original selected native service".into(),
            );
        }
    } else if !action["service"].is_null() {
        return Err("current native actor substituted an unrelated service observation".into());
    }
    if native["caller"] != action["frontend"]
        || native["caller_uid"] != before["caller_uid"]
        || native["target_uid"] == native["caller_uid"]
        || native["target_uid"] == native["init_uid"]
        || native["init_nondumpable"] != true
        || native["supplementary_groups"] != json!([])
        || native["no_new_privileges"] != true
        || native["capabilities_empty"] != true
    {
        return Err(
            "prepared native caller and fixed target boundary differ from original observed actor"
                .into(),
        );
    }
    let after = document("journal-after.json")?;
    closed(&after, journal_fields)?;
    if after["association"] != association || after["request"] != prepared["request"] {
        return Err("retained durable terminal selects another original attempt".into());
    }
    if scenario != "journal-barrier" {
        let ack = document("prepared-ack.json")?;
        closed(
            &ack,
            &["format", "revision", "association", "prepared_sha256"],
        )?;
        if ack
            != json!({"format":"memcordon.workload-prepared-ack","revision":1,"association":association,"prepared_sha256":crate::sha256(&prepared_bytes)})
            || action["prepared_ack"] != true
            || raw("released-stdout.bin")?.is_empty()
            || action["released_stdout"] != crate::sha256(&raw("released-stdout.bin")?)
        {
            return Err("actual prepared acknowledgment/released fixture execution differs".into());
        }
        let released = document("journal-released.json")?;
        if released["association"] != association
            || released["request"] != prepared["request"]
            || released["native"]["exec_observed"] != true
            || released["release"] != "released"
        {
            return Err("actual gated native release lacks durable exec observation".into());
        }
    } else if action["prepared_ack"] != false {
        return Err("journal crash occurred after release acknowledgment".into());
    }
    if scenario == "release-barrier" {
        let result = document("result.json")?;
        if result["format"] != "memcordon.result"
            || result["revision"] != 3
            || result["workload_attempt"] != association
            || result["request"] != prepared["request"]
            || result["provider"] != association["provider"]
            || result["release"] != "released"
            || result["outcome"]["kind"] != "completed"
            || result["outcome"]["wrapper_status"] != 0
            || result["runtime"]["kind"] != "linux-private"
            || result["runtime"]["native"]["exec_observed"] != true
            || document("frontend-wait.json")?["status"] != 0
            || !action["signal"].is_null()
            || !action["victim"].is_null()
        {
            return Err(
                "actual release barrier did not produce the original successful execution".into(),
            );
        }
        cleanup(&result["cleanup"])?;
        super::linux::result_join(&result, &association, &digest, source_commit, true)?;
    } else {
        let expected_victim = match scenario {
            "lost-terminal-response" | "controlled-drain-cancel" => action["frontend"].clone(),
            "released-guardian-loss" => {
                json!({"pid":before["guardian"]["pid"],"birth":before["guardian"]["start_time"]})
            }
            "released-service-loss" => action["service"]["process"].clone(),
            "released-control-loss" => {
                json!({"pid":before["control"]["pid"],"birth":before["control"]["start_time"]})
            }
            _ => json!({"pid":before["worker"]["pid"],"birth":before["worker"]["start_time"]}),
        };
        if action["signal"]
            != if scenario == "controlled-drain-cancel" {
                2
            } else {
                9
            }
            || action["victim"] != expected_victim
            || action["native_signal_result"] != 0
        {
            return Err("actual native fault targeted another original owner".into());
        }
        let recovery = document("recovery.json")?;
        closed(
            &recovery,
            &[
                "format",
                "revision",
                "association",
                "request",
                "release",
                "native",
                "outcome",
                "cleanup",
                "output_delivery",
                "failures",
            ],
        )?;
        if recovery["format"] != "memcordon.linux-workload-terminal"
            || recovery["revision"] != 1
            || recovery["association"] != association
            || recovery["request"] != prepared["request"]
            || document("recovery-process.json")?["status"] != 0
            || after["terminal"]["association"] != association
        {
            return Err(
                "actual cleanup-only recovery did not retain the original lost-response attempt"
                    .into(),
            );
        }
        cleanup(&recovery["cleanup"])?;
        if after["terminal"] != recovery {
            return Err("cleanup-only recovery differs from exact durable native carrier".into());
        }
        recovery_native(&recovery, native)?;
        if let Some(path) = evidence.raw_result.as_deref() {
            if captures.get("result.json").map(String::as_str) != Some(path) {
                return Err("actual frontend result capture reference differs".into());
            }
            let result = document("result.json")?;
            verify_observed_result(
                &result,
                &association,
                &prepared["request"],
                source_commit,
                version,
                true,
                &document("frontend-wait.json")?,
            )?;
        }
        if scenario == "repeated-recovery"
            && (document("recovery-repeat.json")? != recovery
                || document("recovery-repeat-process.json")?["status"] != 0)
        {
            return Err("repeated recovery changed the original durable native outcome".into());
        }
        if scenario == "journal-barrier" && recovery["release"] != "not-released" {
            return Err("durable pre-release journal crash claims a later release".into());
        }
    }
    let acknowledged = document("acknowledgment-process.json")?;
    let response_bytes: Vec<u8> =
        serde_json::from_value(acknowledged["stdout"].clone()).map_err(|e| e.to_string())?;
    let response: Value = crate::wire::decode(&response_bytes)?;
    if acknowledged["status"] != 0
        || response
            != json!({"format":"memcordon.workload-acknowledgment","revision":1,"association":association,"record_retired":true})
    {
        return Err(
            "actual native metadata acknowledgment lacks exact original association".into(),
        );
    }
    if evidence.request.as_ref() != captures.get("request.json")
        || evidence.attempt_observation.as_ref() != captures.get("attempt.json")
        || evidence.invocation != captures["start.json"]
        || evidence.native_observation != captures["held-before.json"]
        || evidence.retirement != captures["action.json"]
        || evidence.authenticated_terminal.as_ref() != captures.get("journal-after.json")
        || evidence.raw_result.as_ref() != captures.get("result.json")
        || evidence.recovery.as_ref() != captures.get("recovery.json")
        || evidence.stdout != captures["stdout.bin"]
        || evidence.stderr != captures["stderr.bin"]
    {
        return Err("native lifecycle evidence substitutes another captured source".into());
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    format: String,
    revision: u32,
    key: crate::CaseKey,
    run_id: String,
    recipe_id: String,
    source_commit: String,
    source_tree_sha256: String,
    actor: String,
    preparation: String,
    captures: BTreeMap<String, String>,
}
pub(super) fn closed(value: &Value, fields: &[&str]) -> VerificationResult<()> {
    let object = value.as_object().ok_or("native component object absent")?;
    if object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str())) {
        return Err("native component fields differ".into());
    }
    Ok(())
}
fn positive(value: &Value) -> VerificationResult<u64> {
    value
        .as_u64()
        .filter(|n| *n > 0)
        .ok_or_else(|| "actual native identity is absent".into())
}
pub fn validate_snapshot_budget(
    runtime: &Value,
    input: &Value,
    configured: u64,
    headroom: u64,
) -> VerificationResult<()> {
    if configured == 0 || !configured.is_multiple_of(1024 * 1024) || headroom == 0 {
        return Err("current snapshot memory operand is not a positive MiB value".into());
    }
    for page in [4096_u64, 16384, 65536] {
        let mut bytes = headroom
            .checked_add(128 * 1024 * 1024)
            .ok_or("snapshot budget overflow")?;
        for manifest in [runtime, input] {
            if manifest["format"] != "memcordon.workload-snapshot" || manifest["revision"] != 1 {
                return Err("unsupported current snapshot format".into());
            }
            let entries = manifest["entries"]
                .as_array()
                .ok_or("snapshot entries absent")?;
            if entries.len() > 16384 {
                return Err("snapshot entry bound exceeded".into());
            }
            for entry in entries {
                bytes = bytes
                    .checked_add(page * 2)
                    .ok_or("snapshot entry accounting overflow")?;
                match entry["kind"].as_str() {
                    Some("regular") => {
                        let size = entry["size"]
                            .as_u64()
                            .filter(|size| *size <= 1024 * 1024 * 1024)
                            .ok_or("snapshot member size invalid")?;
                        bytes = bytes
                            .checked_add(
                                size.checked_add(page - 1)
                                    .ok_or("snapshot rounding overflow")?
                                    / page
                                    * page,
                            )
                            .ok_or("snapshot byte accounting overflow")?;
                    }
                    Some("directory" | "symlink") => {}
                    _ => return Err("unknown current snapshot entry kind".into()),
                }
            }
        }
        let expected = bytes
            .checked_add(1024 * 1024 - 1)
            .ok_or("snapshot MiB accounting overflow")?
            / (1024 * 1024)
            * (1024 * 1024);
        if expected == configured {
            return Ok(());
        }
    }
    Err("configured memory does not include actual snapshot pages, metadata/setup and scenario headroom".into())
}

pub(super) fn verify_observed_result(
    result: &Value,
    association: &Value,
    binding: &Value,
    source_commit: &str,
    version: &str,
    released: bool,
    wait: &Value,
) -> VerificationResult<()> {
    if result["runtime"]["kind"] == "linux-private" {
        super::linux::result_join(
            result,
            association,
            binding["request_sha256"]
                .as_str()
                .ok_or("original request digest absent")?,
            source_commit,
            released,
        )?;
    } else {
        closed(
            result,
            &[
                "format",
                "revision",
                "tool",
                "invocation",
                "request",
                "provider",
                "workload_attempt",
                "release",
                "outcome",
                "cleanup",
                "delivery",
                "output_delivery",
                "diagnostics",
                "provider_failure",
                "request_rejection",
                "windows_rejection",
                "windows_attempt",
                "runtime",
            ],
        )?;
        closed(&result["runtime"], &["kind", "profile"])?;
        closed(
            &result["outcome"],
            &["kind", "native_termination", "wrapper_status"],
        )?;
        if result["format"] != "memcordon.result"
            || result["revision"] != 3
            || result["tool"]["version"] != version
            || result["provider"] != association["provider"]
            || result["workload_attempt"] != *association
            || result["request"] != *binding
            || result["runtime"]["kind"] != "preparation-failed"
            || result["runtime"]["profile"] != "linux-private-workload-v1"
            || result["outcome"]["kind"] != "launch-failure"
            || !result["outcome"]["native_termination"].is_null()
            || result["outcome"]["wrapper_status"] == 0
            || (result["release"] != "unknown" && (released || result["release"] != "not-released"))
            || result["cleanup"]["state"] != "unknown"
            || result["cleanup"]["obligations"] != json!([])
            || result["delivery"] != "complete"
            || !result["request_rejection"].is_null()
            || !result["windows_attempt"].is_null()
            || !result["windows_rejection"].is_null()
        {
            return Err("lost transport frontend invented original execution/release/cleanup facts or another request".into());
        }
    }
    if result["outcome"]["wrapper_status"] != wait["status"] {
        return Err("actual original frontend report differs from its direct wait".into());
    }
    Ok(())
}

pub(super) fn cleanup(value: &Value) -> VerificationResult<()> {
    let obligations = value["obligations"]
        .as_array()
        .ok_or("native cleanup inventory absent")?;
    let mut names = BTreeSet::new();
    for obligation in obligations {
        closed(obligation, &["resource", "settled"])?;
        let name = obligation["resource"]
            .as_str()
            .ok_or("native resource name absent")?;
        if ![
            "aggregate",
            "target",
            "namespace-init",
            "guardian",
            "relays",
            "control-handles",
            "root-references",
            "staging",
            "footprint",
            "record",
            "outputs",
        ]
        .contains(&name)
            || !names.insert(name)
            || obligation["settled"] != true
        {
            return Err("native cleanup has unresolved/unknown/duplicate resource".into());
        }
    }
    if value["state"] != "complete"
        || [
            "aggregate",
            "target",
            "namespace-init",
            "guardian",
            "relays",
            "control-handles",
            "root-references",
            "staging",
            "footprint",
        ]
        .iter()
        .any(|name| !names.contains(name))
    {
        return Err("native original attempt cleanup is incomplete".into());
    }
    Ok(())
}

pub(super) fn recovery_native(recovery: &Value, prepared: &Value) -> VerificationResult<()> {
    let native = &recovery["native"];
    if native.is_null() {
        if recovery["release"] == "released"
            || matches!(
                recovery["outcome"]["kind"].as_str(),
                Some("exited" | "signaled")
            )
        {
            return Err("lost-response recovery invented an original native execution".into());
        }
        return Ok(());
    }
    let mutable = [
        "exec_observed",
        "release_monotonic_millis",
        "exec_observed_monotonic_millis",
        "native_wait_status",
        "memory_oom_kill_count",
        "memory_oom_event_count",
        "memory_max_bytes",
    ];
    let base = prepared
        .as_object()
        .ok_or("actual prepared native facts absent")?;
    let actual = native
        .as_object()
        .ok_or("native recovery is not an object")?;
    if actual.len() != base.len()
        || actual.iter().any(|(name, value)| {
            !base.contains_key(name) || (!mutable.contains(&name.as_str()) && value != &base[name])
        })
    {
        return Err(
            "recovery changed original native process/credential/root/filter identities".into(),
        );
    }
    let exec = native["exec_observed"]
        .as_bool()
        .ok_or("actual exec knowledge absent")?;
    if exec {
        let release = positive(&native["release_monotonic_millis"])?;
        let observed = positive(&native["exec_observed_monotonic_millis"])?;
        if recovery["release"] != "released" || observed < release {
            return Err("recovery exec observation contradicts original release timing".into());
        }
    } else if !native["exec_observed_monotonic_millis"].is_null() {
        return Err("unobserved execution has a fabricated exec timestamp".into());
    }
    match recovery["outcome"]["kind"].as_str() {
        Some("exited") => {
            let status = native["native_wait_status"]
                .as_i64()
                .ok_or("original exit lacks actual wait")?;
            if !exec
                || status & 0x7f != 0
                || recovery["outcome"]["code"].as_i64() != Some((status >> 8) & 0xff)
            {
                return Err("recovery exit differs from original direct wait".into());
            }
        }
        Some("signaled") => {
            let status = native["native_wait_status"]
                .as_i64()
                .ok_or("original signal lacks actual wait")?;
            if !exec
                || !(1..0x7f).contains(&(status & 0x7f))
                || recovery["outcome"]["signal"].as_i64() != Some(status & 0x7f)
            {
                return Err("recovery signal differs from original direct wait".into());
            }
        }
        Some(
            "unknown"
            | "frontend-lost"
            | "native-failure"
            | "controlled-cancellation"
            | "deadline"
            | "memory-limit"
            | "setup-failure",
        ) => {}
        _ => return Err("unknown recovery native outcome variant".into()),
    }
    Ok(())
}

pub fn verify(
    evidence: &CaseEvidenceV2,
    input: &Value,
    build: &ComponentBuild,
    version: &str,
    resolve: &dyn Fn(&str) -> VerificationResult<Vec<u8>>,
) -> VerificationResult<()> {
    let receipt: Receipt = crate::wire::decode(&resolve(&evidence.semantic_observation)?)?;
    let scenario = evidence.key.scenario.as_str();
    let family = if ["release-barrier", "journal-barrier"].contains(&scenario) {
        "L-VER-01"
    } else {
        "L-LIFE-04"
    };
    let actor = build
        .actor_executable
        .as_deref()
        .ok_or("current lifecycle actor role absent")?;
    if receipt.format != "memcordon.current-native-lifecycle-component"
        || receipt.revision != 1
        || receipt.key != evidence.key
        || receipt.run_id != evidence.run_id
        || receipt.recipe_id != build.recipe_id
        || receipt.source_commit != build.source_commit
        || receipt.source_tree_sha256 != build.source_tree_sha256
        || receipt.actor != actor
        || evidence.fixture != actor
        || receipt.key.family != family
        || evidence.key.channel.is_some()
        || evidence.key.evidence_class != crate::EvidenceClass::NativeComponentRegression
        || input
            != &json!({"format":"memcordon.current-native-component-input","revision":1,"key":evidence.key,"run_id":evidence.run_id,"scenario":scenario})
    {
        return Err("actual native lifecycle actor/input/source association differs".into());
    }
    let actor_bytes = resolve(actor)?;
    let actor_sha = crate::sha256(&actor_bytes);
    if actor_sha != evidence.fixture_sha256 {
        return Err("native lifecycle actor bytes differ".into());
    }
    let preparation: Value = crate::wire::decode(&resolve(&receipt.preparation)?)?;
    if preparation["format"] != 1
        || preparation["inputs"]["kind"] != "readiness"
        || preparation["inputs"]["source"]["commit"] != build.source_commit
        || preparation["inputs"]["source"]["version"] != version
        || preparation["inputs"]["host"] != build.target
        || preparation["inputs"]["invocation"]["run"] != evidence.run_id
        || !preparation["files"].as_array().is_some_and(|files| {
            files.iter().any(|file| {
                file["sha256"] == actor_sha
                    && file["size"] == actor_bytes.len() as u64
                    && file["executable"] == true
            })
        })
    {
        return Err(
            "native lifecycle controller is not the exact original source-prepared image".into(),
        );
    }
    verify_observations(
        evidence,
        scenario,
        &build.source_commit,
        &build.target,
        version,
        &receipt.captures,
        resolve,
    )
}
