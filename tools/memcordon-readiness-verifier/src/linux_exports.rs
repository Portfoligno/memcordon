//! Export refusal acceptance joins native object custody to the original request.
use crate::{CaseKey, VerificationResult};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxImageExportEvidence {
    pub format: String,
    pub revision: u32,
    pub key: CaseKey,
    pub run_id: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub lease_id: String,
    pub owner: String,
    pub original_lease_owner: String,
    pub observation: String,
    pub challenge: String,
    pub activation: String,
    pub policy: String,
    pub contract: String,
    pub provider_request: String,
    pub result: String,
    pub prepared: String,
    pub prepared_native: String,
    pub ready: String,
    pub native_source: String,
    pub native_worker: String,
    pub invocation: String,
    pub native_wait: String,
    pub native_family: String,
    pub stdout: String,
    pub stderr: String,
    pub controller_setup: Option<String>,
    pub external: BTreeMap<String, String>,
    pub recovery: String,
    pub recovery_artifacts: BTreeMap<String, String>,
}
impl LinuxImageExportEvidence {
    pub fn artifact_paths(&self) -> Vec<&str> {
        let mut paths = vec![
            self.owner.as_str(),
            &self.original_lease_owner,
            &self.observation,
            &self.challenge,
            &self.activation,
            &self.policy,
            &self.contract,
            &self.provider_request,
            &self.result,
            &self.prepared,
            &self.prepared_native,
            &self.ready,
            &self.native_source,
            &self.native_worker,
            &self.invocation,
            &self.native_wait,
            &self.native_family,
            &self.stdout,
            &self.stderr,
            &self.recovery,
        ];
        if let Some(path) = &self.controller_setup {
            paths.push(path);
        }
        paths.extend(self.external.values().map(String::as_str));
        paths.extend(self.recovery_artifacts.values().map(String::as_str));
        paths
    }
}
fn closed(value: &Value, fields: &[&str]) -> VerificationResult<()> {
    let object = value
        .as_object()
        .ok_or("native export graph node is not an object")?;
    if object.len() != fields.len() || object.keys().any(|field| !fields.contains(&field.as_str()))
    {
        return Err("native export graph node has missing/unknown fields".into());
    }
    Ok(())
}
pub(crate) fn verify_export(
    index: &crate::EvidenceIndex,
    record: &crate::CaseRecord,
    e: &LinuxImageExportEvidence,
    products: &BTreeMap<crate::ProductKey, &crate::ProductObservation>,
    custody: &crate::custody::Custody,
) -> VerificationResult<()> {
    crate::header(
        &e.format,
        e.revision,
        "memcordon.consumer-readiness.linux-image-export",
    )?;
    let origin = crate::producer_origin(index, &record.key.target, record.key.channel.as_deref())?;
    let scenario = record
        .key
        .scenario
        .strip_prefix("export-")
        .filter(|value| {
            matches!(
                *value,
                "symlink" | "fifo" | "device" | "socket" | "traversal" | "concurrent-writer"
            )
        })
        .ok_or("export row outside finite frozen matrix")?;
    if e.key != record.key
        || e.run_id != origin.run_id
        || e.source_commit != index.source_commit
        || e.source_tree_sha256 != index.source_tree_sha256
        || record.key.evidence_class != crate::EvidenceClass::InstalledProduct
        || record.key.family != "L-IMG-04"
        || !record.key.target.ends_with("linux-gnu")
    {
        return Err("export row crosses source/origin/native applicability".into());
    }
    for path in e.artifact_paths() {
        custody.bytes(path)?;
    }
    let product = products
        .get(&crate::ProductKey {
            target: record.key.target.clone(),
            channel: record
                .key
                .channel
                .clone()
                .ok_or("export installed channel absent")?,
        })
        .copied()
        .ok_or("export original selected installed product absent")?;
    let (owner, checkpoint) = validate_original_export_owner(index, record, e, product, custody)?;
    let row = crate::wire::json(custody.bytes(&e.observation)?)?;
    closed(
        &row,
        &[
            "family",
            "scenario",
            "fixture_mode",
            "challenge",
            "contract",
            "activation",
            "prepared",
            "prepared_native",
            "ready",
            "controller_setup",
            "native_source",
            "native_invocation",
            "native_wait",
            "native_family",
            "provider_request",
            "recovery",
            "stdout",
            "stderr",
            "result",
            "native_exit",
            "error",
        ],
    )?;
    let directory = format!(
        "{}/{}",
        owner["output"]
            .as_str()
            .ok_or("export original output scope absent")?,
        record.key.scenario
    );
    if row["family"] != record.key.family
        || row["scenario"] != record.key.scenario
        || row["fixture_mode"] != scenario
        || !row["error"].is_null()
    {
        return Err("export original producer scenario/failure differs".into());
    }
    let prefix = e
        .observation
        .strip_suffix("/observation.json")
        .ok_or("export original observation archive leaf differs")?;
    for (field, path, leaf) in [
        ("challenge", &e.challenge, "challenge.bin"),
        ("contract", &e.contract, "request.json"),
        ("activation", &e.activation, "mixed.activation.json"),
        ("prepared", &e.prepared, "prepared.json"),
        (
            "prepared_native",
            &e.prepared_native,
            "prepared-native.json",
        ),
        ("ready", &e.ready, "ready.json"),
        (
            "native_source",
            &e.native_source,
            "native-export-source.json",
        ),
        (
            "native_invocation",
            &e.invocation,
            "frontend-invocation.json",
        ),
        ("native_wait", &e.native_wait, "frontend-native-wait.json"),
        (
            "native_family",
            &e.native_family,
            "native-family-retirement.json",
        ),
        ("recovery", &e.recovery, "export-recovery.json"),
        ("stdout", &e.stdout, "launch/stdout.bin"),
        ("stderr", &e.stderr, "launch/stderr.bin"),
        ("result", &e.result, "launch/result.json"),
    ] {
        if path != &format!("{prefix}/{leaf}") || row[field] != format!("{directory}/{leaf}") {
            return Err(format!(
                "export original {field} native/archive scope differs"
            ));
        }
    }
    if e.policy != format!("{prefix}/mixed.policy.json")
        || e.native_worker != format!("{prefix}/export-worker.json")
    {
        return Err("export actual policy/worker archive leaves cross original scenario".into());
    }
    let expected: std::collections::BTreeSet<&str> = if scenario == "concurrent-writer" {
        [
            "writer-held.json",
            "writer-native-held.json",
            "writer-retired.json",
            "external-helper-setup.json",
            "external-helper-invocation.json",
            "external-helper-held.json",
            "external-helper-armed.json",
            "external-helper-event.json",
            "external-family-retirement.json",
            "external-cgroup-retirement.json",
            "external-helper-ack.json",
            "external-administrative-closure.json",
            "external-helper-settled.json",
            "external-helper-retirement.json",
            "external-helper-stdout.bin",
            "external-helper-stderr.bin",
        ]
        .into_iter()
        .collect()
    } else if scenario == "device" {
        ["device-admin-handles-retired.json"].into_iter().collect()
    } else {
        std::collections::BTreeSet::new()
    };
    if e.external
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>()
        != expected
        || e.external
            .iter()
            .any(|(leaf, path)| path != &format!("{prefix}/{leaf}"))
    {
        return Err("export selected native external artifact closure differs".into());
    }
    let controller_leaf = match scenario {
        "device" => Some("device-created.json"),
        "concurrent-writer" => Some("writer-held.json"),
        _ => None,
    };
    if let Some(leaf) = controller_leaf
        && (e.controller_setup.as_deref() != Some(format!("{prefix}/{leaf}").as_str())
            || row["controller_setup"] != format!("{directory}/{leaf}"))
    {
        return Err(
            "export actual controller native/archive path crosses original scenario".into(),
        );
    }
    for (field, path) in &e.recovery_artifacts {
        let leaf = if field == "original_journal" {
            "recovery-original-journal.bin".to_owned()
        } else {
            format!(
                "recovery-{field}.{}",
                if ["stdout", "stderr"].contains(&field.as_str()) {
                    "bin"
                } else {
                    "json"
                }
            )
        };
        if path != &format!("{prefix}/{leaf}") {
            return Err(
                "export recovery capture crosses original immutable native scenario".into(),
            );
        }
    }
    let (prepared, attempt) =
        validate_export_execution_graph(e, &owner, &checkpoint, product, custody)?;
    let request_leaf = format!("launch/observations/{attempt}.provider-request.bin");
    if row["provider_request"] != format!("{directory}/{request_leaf}")
        || e.provider_request != format!("{prefix}/{request_leaf}")
    {
        return Err(
            "export actual authenticated request native/archive path crosses original attempt"
                .into(),
        );
    }
    let wait = crate::wire::json(custody.bytes(&e.native_wait)?)?;
    if row["native_exit"] != wait["native_exit"] {
        return Err("export producer native exit projection differs".into());
    }
    validate_export_ready(e, &prepared, custody)?;
    validate_export_held_family(e, &owner, &prepared, &attempt, product, custody)?;
    match scenario {
        "device" => validate_export_device(e, &prepared, custody)?,
        "concurrent-writer" => {
            validate_export_preempty_writer(e, &prepared, custody)?;
            validate_export_external_helper(e, &owner, &checkpoint, &prepared, custody)?;
        }
        _ => {
            if e.controller_setup.is_some() || !row["controller_setup"].is_null() {
                return Err("export added undeclared controller authority".into());
            }
        }
    }
    validate_export_recovery(e, &owner, &prepared, &attempt, product, custody)
}
pub(crate) fn validate_original_export_owner(
    index: &crate::EvidenceIndex,
    record: &crate::CaseRecord,
    e: &LinuxImageExportEvidence,
    product: &crate::ProductObservation,
    custody: &crate::custody::Custody,
) -> VerificationResult<(Value, Value)> {
    let decode = |path: &str| crate::wire::json(custody.bytes(path)?);
    let owner = decode(&e.owner)?;
    let lease = decode(&e.original_lease_owner)?;
    closed(
        &owner,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "lease_id",
            "provider",
            "account",
            "expected_agent_sha256",
            "output",
            "admin_root",
            "image_admin_root",
            "admin_root_device",
            "admin_root_inode",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
    )?;
    closed(
        &owner["identity"],
        &["run_id", "source_commit", "source_tree_sha256", "version"],
    )?;
    closed(&owner["cell"], &["target", "channel"])?;
    closed(
        &owner["provider"],
        &["generation", "source_commit", "runtime_manifest_sha256"],
    )?;
    closed(
        &owner["account"],
        &[
            "name",
            "uid",
            "gid",
            "intent",
            "native_readback",
            "group_readback",
        ],
    )?;
    closed(
        &lease,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "admin_root",
            "device",
            "inode",
            "cleanup_agent",
            "cleanup_agent_sha256",
            "legacy",
            "lease_id",
            "artifact_root",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
    )?;
    let agent = product
        .components
        .iter()
        .find(|component| component.role == "sealed-agent")
        .ok_or("export selected installed agent absent")?;
    let key = crate::ProductKey {
        target: record.key.target.clone(),
        channel: record
            .key
            .channel
            .clone()
            .ok_or("export installed channel absent")?,
    };
    let admin = owner["admin_root"]
        .as_str()
        .ok_or("export original native administrative scope absent")?;
    let output = owner["output"]
        .as_str()
        .ok_or("export actual original observation scope absent")?;
    let acquisition_prefix = e
        .owner
        .strip_suffix("/mixed-cases/image-cases/owner.json")
        .ok_or("export owner crosses original acquisition scope")?;
    let artifact_root = lease["artifact_root"]
        .as_str()
        .ok_or("export original artifact root absent")?;
    if !artifact_root.starts_with('/')
        || artifact_root.contains('\0')
        || artifact_root
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
        || output != format!("{artifact_root}/{acquisition_prefix}/mixed-cases/image-cases")
    {
        return Err("export native output crosses original acquisition artifact root".into());
    }
    if e.original_lease_owner != format!("{acquisition_prefix}/lease-owner.json")
        || e.lease_id != product.lifecycle.lease_id
        || [admin, output].iter().any(|path| {
            !path.starts_with('/')
                || path
                    .split('/')
                    .skip(1)
                    .any(|part| part.is_empty() || part == "." || part == "..")
        })
        || owner["format"] != "memcordon.linux-image-case-owner"
        || owner["revision"] != 1
        || owner["identity"]["run_id"] != e.run_id
        || owner["identity"]["source_commit"] != e.source_commit
        || owner["identity"]["source_tree_sha256"] != e.source_tree_sha256
        || owner["identity"]["version"] != product.version
        || owner["cell"] != serde_json::to_value(&key).map_err(|error| error.to_string())?
        || owner["lease_id"] != e.lease_id
        || owner["expected_agent_sha256"] != agent.installed_sha256
        || owner["image_admin_root"] != format!("{admin}/image-cases/{}", e.lease_id)
        || owner["provider"]["generation"] != format!("{}:{}", product.version, e.source_commit)
        || owner["provider"]["source_commit"] != e.source_commit
        || owner["provider"]["runtime_manifest_sha256"]
            != custody.hash(&product.runtime_manifest)?
        || owner["account"]["name"]
            .as_str()
            .is_none_or(|value| value.is_empty())
        || ["uid", "gid"].iter().any(|field| {
            owner["account"][field]
                .as_u64()
                .is_none_or(|value| value == 0 || value > u32::MAX as u64)
        })
        || lease["format"] != "memcordon.consumer-readiness.linux-lease-owner"
        || lease["revision"] != 1
        || lease["identity"] != owner["identity"]
        || lease["cell"] != owner["cell"]
        || lease["lease_id"] != owner["lease_id"]
        || lease["admin_root"] != admin
        || lease["device"] != owner["admin_root_device"]
        || lease["inode"] != owner["admin_root_inode"]
        || lease["cleanup_agent_sha256"] != agent.installed_sha256
        || lease["work_deadline_unix_millis"] != owner["work_deadline_unix_millis"]
        || lease["cleanup_deadline_unix_millis"] != owner["cleanup_deadline_unix_millis"]
        || lease["work_deadline_unix_millis"]
            .as_u64()
            .is_none_or(|value| value == 0)
        || lease["cleanup_deadline_unix_millis"].as_u64()
            <= lease["work_deadline_unix_millis"].as_u64()
    {
        return Err("export source/product/original lifetime acquisition differs".into());
    }
    let lifecycle: crate::InstalledLifecycleJournal =
        crate::wire::decode(custody.bytes(&product.lifecycle.journal)?)?;
    let roots = lifecycle
        .events
        .iter()
        .filter(|event| {
            event.phase == "owned-before-mutation"
                && event.operation == "administrative-staging-created"
                && event.succeeded
        })
        .collect::<Vec<_>>();
    if lifecycle.run_id != e.run_id
        || lifecycle.lease_id != e.lease_id
        || lifecycle.source_commit != e.source_commit
        || lifecycle.source_tree_sha256 != e.source_tree_sha256
        || roots.len() != 1
    {
        return Err("export lacks original native root acquisition journal".into());
    }
    let root = decode(&roots[0].native_receipt)?;
    closed(&root, &["path", "device", "inode"])?;
    if root["path"] != admin || root["device"] != lease["device"] || root["inode"] != lease["inode"]
    {
        return Err("export original acquired protected root inode differs".into());
    }
    let checkpoints = index
        .artifacts
        .iter()
        .filter(|artifact| artifact.path.ends_with("/owned-resources-acquired.json"))
        .map(|artifact| decode(&artifact.path))
        .collect::<VerificationResult<Vec<_>>>()?;
    let checkpoints = checkpoints
        .iter()
        .filter(|value| {
            value["identity"] == owner["identity"]
                && value["cell"] == owner["cell"]
                && value["admin_root"] == owner["admin_root"]
        })
        .collect::<Vec<_>>();
    if checkpoints.len() != 1 {
        return Err(
            "export original exclusive account/image acquisition absent or ambiguous".into(),
        );
    }
    let checkpoint = checkpoints[0];
    closed(
        checkpoint,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "admin_root",
            "device",
            "inode",
            "legacy",
            "images",
            "account",
        ],
    )?;
    if checkpoint["format"] != "memcordon.owned-readiness-resources"
        || checkpoint["revision"] != 1
        || checkpoint["account"] != owner["account"]
        || checkpoint["legacy"] != lease["legacy"]
        || checkpoint["device"] != lease["device"]
        || checkpoint["inode"] != lease["inode"]
    {
        return Err("export original acquisition account/policy/native inode differs".into());
    }
    Ok((owner, checkpoint.clone()))
}

pub(crate) fn validate_export_execution_graph(
    e: &LinuxImageExportEvidence,
    owner: &Value,
    checkpoint: &Value,
    product: &crate::ProductObservation,
    custody: &crate::custody::Custody,
) -> VerificationResult<(Value, String)> {
    let decode = |path: &str| crate::wire::json(custody.bytes(path)?);
    let scenario = e
        .key
        .scenario
        .strip_prefix("export-")
        .filter(|scenario| {
            [
                "symlink",
                "fifo",
                "device",
                "socket",
                "traversal",
                "concurrent-writer",
            ]
            .contains(scenario)
        })
        .ok_or("unfrozen native export scenario")?;
    let challenge = custody.bytes(&e.challenge)?;
    if challenge.len() != 32 || challenge.iter().all(|byte| *byte == 0) {
        return Err("original export challenge absent".into());
    }
    let challenge_hex = hex::encode(challenge);
    let contract = decode(&e.contract)?;
    let policy = decode(&e.policy)?;
    let activation = decode(&e.activation)?;
    crate::wire::validate_request(
        custody.bytes(&e.contract)?,
        &e.key,
        crate::OutcomeOrigin::Target,
    )?;
    if crate::linux_policy::activation_registry(&activation)? != &policy
        || activation["registry_digest"] != crate::linux_registry_digest(&policy, &e.key.target)?
        || contract["expected_epoch"] != activation["epoch"]
        || policy["legacy"] != checkpoint["legacy"]
        || contract["runtime_image"]
            != crate::linux_image_reference(&checkpoint["images"]["runtime"], &e.key.target)?
        || contract["input_image"]
            != crate::linux_image_reference(&checkpoint["images"]["input"], &e.key.target)?
        || policy["execution_identities"]
            .as_array()
            .is_none_or(|rows| {
                rows.len() != 1
                    || rows[0]["uid"] != owner["account"]["uid"]
                    || rows[0]["gid"] != owner["account"]["gid"]
                    || rows[0]["enabled"] != true
            })
        || policy["root_layouts"].as_array().is_none_or(|rows| {
            rows.len() != 1
                || rows[0]["runtime_image"] != contract["runtime_image"]
                || rows[0]["input_image"] != contract["input_image"]
                || rows[0]["output_files"]
                    != serde_json::json!([if scenario == "traversal" {
                        "work/parent/exported.bin"
                    } else {
                        "work/exported.bin"
                    }])
        })
    {
        return Err(
            "export actual activation crosses original image/account/output selection".into(),
        );
    }
    let expected_requirements = if scenario == "socket" {
        serde_json::json!([{"kind":"unix_path_stream","id":"pathname","writable_root":"work"}])
    } else {
        serde_json::json!([])
    };
    if contract["requirements"] != expected_requirements {
        return Err("export contract adds unrelated native authority requirements".into());
    }
    let execution = &policy["execution_identities"][0];
    let layout = &policy["root_layouts"][0];
    let exclusive = crate::linux_images::owned_exclusive_declaration_reference(
        &owner["identity"],
        &owner["cell"],
        &owner["account"],
    )?;
    let identity_ref = crate::linux_registry::linux_identity_reference(execution)?;
    let layout_ref = crate::linux_registry::linux_root_layout_reference(layout)?;
    let images = policy["images"]
        .as_array()
        .ok_or("export activated original image catalogue absent")?;
    let grants = policy["grants"]
        .as_array()
        .ok_or("export actual sole grant absent")?;
    if contract["authorized_profile"] != crate::linux_registry::linux_combined_profile_reference()
        || contract["execution_identity"]
            != serde_json::json!({"identity":identity_ref,"exclusive_use_policy":exclusive})
        || execution["identity_id"] != "owned-readiness-identity"
        || execution["exclusive_use_policy"] != exclusive
        || execution["supplementary_groups"] != serde_json::json!([])
        || execution["reservation_key"] != "owned-readiness-reservation"
        || contract["root_layout"] != layout_ref
        || layout["layout_id"] != "owned-readiness-root"
        || layout["writable_roots"]
            != serde_json::json!([{"id":"work","path":"work","byte_limit":16u64*1024*1024*1024,"generated_execution":true}])
        || images.len() != 2
        || !images.contains(&checkpoint["images"]["runtime"])
        || !images.contains(&checkpoint["images"]["input"])
        || grants.len() != 1
        || grants[0]["enabled"] != true
        || grants[0]["callers"] != serde_json::json!([{"platform":"linux","uid":65534}])
        || grants[0]["id"] != contract["authorization"]["grant_id"]
        || grants[0]["revision"] != contract["authorization"]["grant_revision"]
        || grants[0]["approved_plans"] != serde_json::json!([contract["workload_plan_digest"]])
        || grants[0]["profile"] != contract["authorized_profile"]
        || [
            "execution_identity",
            "runtime_image",
            "input_image",
            "root_layout",
        ]
        .iter()
        .any(|field| grants[0][*field] != contract[*field])
        || contract["workload_plan_digest"] != crate::linux_images::owned_plan_digest(&contract)?
        || contract["authorization"]["approved_plan_digest"] != contract["workload_plan_digest"]
        || contract["launch"]
            != serde_json::json!({"entrypoint":"owned-readiness","working_directory":"work"})
        || policy["active_attempt_disposition"] != "drain-existing"
    {
        return Err("export original acquired catalogue/exclusive identity/root/actual grant/plan/profile differ".into());
    }
    let prepared = decode(&e.prepared)?;
    let native = decode(&e.prepared_native)?;
    closed(
        &prepared,
        &[
            "format",
            "revision",
            "provider",
            "admission",
            "caller",
            "target",
            "namespace_init",
            "guardian",
            "user_namespace",
            "mount_namespace",
            "pid_namespace",
            "network_namespace",
            "ipc_namespace",
            "root_device",
            "root_inode",
            "authorizes_launch",
        ],
    )?;
    closed(
        &native,
        &[
            "format",
            "revision",
            "run_id",
            "attempt_id",
            "prepared_sha256",
            "observer",
            "held_before_authorization",
            "target",
            "namespace_init",
            "guardian",
            "caller",
            "root_device",
            "root_inode",
        ],
    )?;
    closed(&native["observer"], &["pid", "birth"])?;
    closed(
        &prepared["admission"],
        &[
            "format",
            "revision",
            "attempt_id",
            "request",
            "request_sha256",
            "invocation_sha256",
            "caller_uid",
            "registry_digest",
            "epoch",
            "admission_nonce",
            "profile_id",
        ],
    )?;
    let nonce: Vec<u8> = serde_json::from_value(prepared["admission"]["admission_nonce"].clone())
        .map_err(|error| error.to_string())?;
    let attempt = prepared["admission"]["attempt_id"]
        .as_str()
        .filter(|value| {
            value.len() == 32
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or("native original export attempt invalid")?
        .to_owned();
    if prepared["format"] != "memcordon.mixed-prepared-observation"
        || prepared["revision"] != 2
        || prepared["provider"] != owner["provider"]
        || prepared["authorizes_launch"] != false
        || prepared["admission"]["format"] != "memcordon.private-admission-metadata"
        || prepared["admission"]["revision"] != 2
        || prepared["admission"]["request"] != contract
        || prepared["admission"]["caller_uid"] != 65534
        || prepared["admission"]["registry_digest"] != activation["registry_digest"]
        || prepared["admission"]["epoch"] != activation["epoch"]
        || prepared["admission"]["profile_id"] != contract["authorized_profile"]
        || nonce.len() != 16
        || nonce.iter().all(|byte| *byte == 0)
        || native["format"] != "memcordon.linux-prepared-native-observation"
        || native["revision"] != 1
        || native["run_id"] != e.run_id
        || native["attempt_id"] != attempt
        || native["prepared_sha256"] != custody.hash(&e.prepared)?
        || native["held_before_authorization"] != true
        || native["root_device"] != prepared["root_device"]
        || native["root_inode"] != prepared["root_inode"]
        || ["pid", "birth"].iter().any(|field| {
            native["observer"][field]
                .as_u64()
                .is_none_or(|value| value == 0)
        })
    {
        return Err("export actual protected preparation/native held receipt differs".into());
    }
    let mut identities = std::collections::BTreeSet::new();
    for role in ["target", "namespace_init", "guardian", "caller"] {
        closed(&prepared[role], &["pid", "birth"])?;
        let snapshot = &native[role];
        closed(
            snapshot,
            &[
                "process_id",
                "birth",
                "namespace_pids",
                "user",
                "mount",
                "pid",
                "network",
                "ipc",
            ],
        )?;
        let pid = snapshot["process_id"]
            .as_u64()
            .filter(|value| *value > 0 && *value <= i32::MAX as u64)
            .ok_or("export original native held PID invalid")?;
        let birth = snapshot["birth"]
            .as_u64()
            .filter(|value| *value > 0)
            .ok_or("export original native held birth invalid")?;
        if !identities.insert((pid, birth))
            || snapshot["process_id"] != prepared[role]["pid"]
            || snapshot["birth"] != prepared[role]["birth"]
            || (native["observer"]["pid"] == pid && native["observer"]["birth"] == birth)
        {
            return Err("export independent observer/held family alias or identity differs".into());
        }
        let pids = snapshot["namespace_pids"]
            .as_array()
            .ok_or("export held namespace PID tuple absent")?;
        if pids.is_empty()
            || pids.len() > 32
            || pids[0] != pid
            || pids.iter().any(|pid| {
                pid.as_u64()
                    .is_none_or(|value| value == 0 || value > i32::MAX as u64)
            })
            || (role == "namespace_init" && pids.last() != Some(&serde_json::json!(1)))
        {
            return Err("export native PID namespace tuple differs".into());
        }
        for (name, field) in [
            ("user", "user_namespace"),
            ("mount", "mount_namespace"),
            ("pid", "pid_namespace"),
            ("network", "network_namespace"),
            ("ipc", "ipc_namespace"),
        ] {
            closed(&snapshot[name], &["device", "inode"])?;
            if snapshot[name]["device"].as_u64().is_none()
                || snapshot[name]["inode"]
                    .as_u64()
                    .is_none_or(|value| value == 0)
                || (["target", "namespace_init"].contains(&role)
                    && snapshot[name] != prepared[field])
            {
                return Err("export original held native namespaces differ".into());
            }
        }
    }
    crate::linux_policy::validate_prepared_native_graph(
        &prepared,
        &native,
        &contract,
        &owner["provider"],
        &activation,
        custody.hash(&e.prepared)?,
        &e.run_id,
        &attempt,
    )?;
    let source = decode(&e.native_source)?;
    validate_linux_export_source(scenario, &source, &native, &owner["account"])?;
    let command = decode(&e.invocation)?;
    let wait = decode(&e.native_wait)?;
    closed(
        &command,
        &[
            "format",
            "revision",
            "program",
            "arguments",
            "environment_cleared",
            "caller_uid",
            "caller_gid",
            "selected_cli_sha256",
        ],
    )?;
    closed(
        &wait,
        &[
            "format",
            "revision",
            "process_id",
            "process_birth",
            "raw_wait_status",
            "native_exit",
            "signal",
            "invocation_sha256",
            "stdout_sha256",
            "stderr_sha256",
        ],
    )?;
    let status = wait["native_exit"]
        .as_i64()
        .filter(|value| (1..=255).contains(value))
        .ok_or("export original frontend did not exit with refusal")? as i32;
    let cli = product
        .components
        .iter()
        .find(|component| component.role == "public-cli")
        .ok_or("export installed original frontend absent")?;
    let program: Vec<u8> =
        serde_json::from_value(command["program"].clone()).map_err(|error| error.to_string())?;
    let args: Vec<Vec<u8>> =
        serde_json::from_value(command["arguments"].clone()).map_err(|error| error.to_string())?;
    if command["format"] != "memcordon.linux-owned-frontend-invocation"
        || command["revision"] != 1
        || program != b"/usr/bin/setpriv"
        || command["environment_cleared"] != true
        || command["caller_uid"] != 65534
        || command["caller_gid"] != 65534
        || command["selected_cli_sha256"] != cli.installed_sha256
        || args.len() != 24
        || wait["format"] != "memcordon.linux-policy-frontend-exit"
        || wait["revision"] != 1
        || wait["process_id"] != prepared["caller"]["pid"]
        || wait["process_birth"] != prepared["caller"]["birth"]
        || wait["raw_wait_status"] != status * 256
        || !wait["signal"].is_null()
        || wait["invocation_sha256"] != custody.hash(&e.invocation)?
        || wait["stdout_sha256"] != custody.hash(&e.stdout)?
        || wait["stderr_sha256"] != custody.hash(&e.stderr)?
    {
        return Err("export actual frontend command/wait/capture joins differ".into());
    }
    for (index, text) in [
        (0, "--reuid"),
        (1, "65534"),
        (2, "--regid"),
        (3, "65534"),
        (4, "--clear-groups"),
        (5, "--"),
        (6, "/usr/libexec/memcordon"),
        (7, "+512M"),
        (9, "--sealed"),
        (10, "--workload-contract"),
        (12, "--report-format"),
        (13, "result-v2"),
        (14, "--report"),
        (16, "--mixed-observation-directory"),
        (18, "--image-entrypoint"),
        (19, "owned-readiness"),
        (20, "--"),
        (21, "export-object"),
    ] {
        if args[index] != text.as_bytes() {
            return Err("export frontend invoked unrelated authority/work".into());
        }
    }
    let row = decode(&e.observation)?;
    for (index, field) in [(11, "contract"), (15, "result")] {
        if args[index]
            != row[field]
                .as_str()
                .ok_or("export original frontend operand absent")?
                .as_bytes()
        {
            return Err("export actual frontend paths cross original case".into());
        }
    }
    let result_parent =
        crate::linux_path::parent(row["result"].as_str().ok_or("export result path absent")?)
            .ok_or("export result parent absent")?;
    if args[17] != crate::linux_path::join(&result_parent, "observations").as_bytes()
        || args[22] != challenge_hex.as_bytes()
        || args[23] != scenario.as_bytes()
    {
        return Err("export public argv/observation scope differs".into());
    }
    let deadline = std::str::from_utf8(&args[8]).map_err(|_| "export deadline not UTF8")?;
    let budget = deadline
        .strip_prefix('+')
        .and_then(|value| value.strip_suffix("ms"))
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0 && *value <= 60_000)
        .ok_or("export original time budget differs")?;
    if deadline != format!("+{budget}ms") {
        return Err("export original time budget not canonical".into());
    }
    let public_args = ["owned-readiness", "export-object", &challenge_hex, scenario]
        .iter()
        .map(|text| serde_json::json!({"display":text,"raw":null}))
        .collect::<Vec<_>>();
    let public = serde_json::json!({"syntax":"plus-budgets-v1","budget_tokens":[{"kind":"memory","token":"+512M"},{"kind":"time","token":deadline}],"memory_token":"+512M","deadline_token":deadline,"argv":public_args});
    let result = decode(&e.result)?;
    crate::wire::validate_linux_public_result_envelope(
        &result,
        &public,
        &product.version,
        &e.key.target,
        status,
        u32::try_from(
            wait["process_id"]
                .as_u64()
                .ok_or("export actual frontend PID absent")?,
        )
        .map_err(|_| "export native frontend PID range differs")?,
    )?;
    let request = decode(&e.provider_request)?;
    closed(
        &request,
        &[
            "format",
            "revision",
            "contract",
            "native_launch",
            "attempt_deadline_millis",
        ],
    )?;
    let request_digest = crate::wire::v3_request_digest(&contract)?;
    if request["format"] != "memcordon.mixed-runtime-request"
        || request["revision"] != 2
        || request["contract"] != contract
        || request["attempt_deadline_millis"].as_u64() != Some(budget)
        || prepared["admission"]["request_sha256"] != request_digest
    {
        return Err("export actual prepared original request digest differs".into());
    }
    let mut launch: Vec<u8> = serde_json::from_value(request["native_launch"].clone())
        .map_err(|error| error.to_string())?;
    launch.extend(hex::decode(&request_digest).map_err(|error| error.to_string())?);
    if prepared["admission"]["invocation_sha256"] != crate::sha256(&launch) {
        return Err("export original authenticated native launch commitment differs".into());
    }
    crate::wire::validate_mixed_public_arguments_and_deadline(
        &launch,
        custody.bytes(&e.contract)?,
        &[
            b"export-object".to_vec(),
            challenge_hex.into_bytes(),
            scenario.as_bytes().to_vec(),
        ],
        &[],
        Some(512 * 1024 * 1024),
        None,
    )?;
    validate_linux_export_outcome(scenario, &result, &attempt, &request_digest, status)?;
    Ok((prepared, attempt))
}
pub(crate) fn validate_export_preempty_writer(
    e: &LinuxImageExportEvidence,
    prepared: &Value,
    custody: &crate::custody::Custody,
) -> VerificationResult<()> {
    let get = |name: &str| -> VerificationResult<Value> {
        crate::wire::json(
            custody.bytes(
                e.external
                    .get(name)
                    .ok_or("export original writer artifact absent")?,
            )?,
        )
    };
    let held = get("writer-held.json")?;
    let native = get("writer-native-held.json")?;
    let retired = get("writer-retired.json")?;
    closed(
        &held,
        &[
            "format",
            "revision",
            "sequence",
            "challenge",
            "root_pid",
            "root_birth",
            "operation",
            "observation",
        ],
    )?;
    closed(
        &held["observation"],
        &["pid", "birth", "parent_pid", "members"],
    )?;
    closed(
        &native,
        &[
            "process_id",
            "birth",
            "namespace_pids",
            "user",
            "mount",
            "pid",
            "network",
            "ipc",
        ],
    )?;
    let pids = native["namespace_pids"]
        .as_array()
        .ok_or("writer original native namespace PID tuple absent")?;
    let selected = crate::wire::json(custody.bytes(&e.prepared_native)?)?;
    let target_pids = selected["target"]["namespace_pids"]
        .as_array()
        .ok_or("writer original parent namespace tuple absent")?;
    if native["process_id"]
        .as_u64()
        .is_none_or(|value| value == 0 || value > i32::MAX as u64)
        || native["birth"].as_u64().is_none_or(|value| value == 0)
        || pids.is_empty()
        || pids[0] != native["process_id"]
        || pids.last() != Some(&held["observation"]["pid"])
        || pids.iter().any(|pid| {
            pid.as_u64()
                .is_none_or(|value| value == 0 || value > i32::MAX as u64)
        })
        || held["observation"]["birth"] != native["birth"]
        || target_pids.last() != Some(&held["observation"]["parent_pid"])
        || held["observation"]["members"] != serde_json::json!([])
    {
        return Err(
            "preempty writer original native host/namespace/parent association differs".into(),
        );
    }
    for field in ["user", "mount", "pid", "network", "ipc"] {
        closed(&native[field], &["device", "inode"])?;
        if native[field] != selected["target"][field] {
            return Err("preempty writer crossed held prepared family namespaces".into());
        }
    }
    if held["format"] != "memcordon.linux-readiness-transcript"
        || held["revision"] != 1
        || held["operation"] != "export-writer-held"
        || held["challenge"] != hex::encode(custody.bytes(&e.challenge)?)
        || held["root_birth"] != prepared["target"]["birth"]
        || target_pids.last() != Some(&held["root_pid"])
    {
        return Err("preempty writer fixture source differs".into());
    }
    closed(
        &retired,
        &["format", "revision", "fixture", "held_retirement"],
    )?;
    let stopped = &retired["fixture"];
    closed(
        stopped,
        &[
            "format",
            "revision",
            "sequence",
            "challenge",
            "root_pid",
            "root_birth",
            "operation",
            "observation",
        ],
    )?;
    closed(
        &stopped["observation"],
        &[
            "pid",
            "native_wait_completed",
            "raw_wait_status",
            "native_exit_code",
            "native_signal",
            "before_root_release",
        ],
    )?;
    let owners = retired["held_retirement"]
        .as_array()
        .ok_or("preempty writer original native owner retirement absent")?;
    if retired["format"] != "memcordon.linux-export-preempty-writer-retirement"
        || retired["revision"] != 1
        || owners.len() != 1
        || stopped["format"] != held["format"]
        || stopped["revision"] != 1
        || stopped["challenge"] != held["challenge"]
        || stopped["root_pid"] != held["root_pid"]
        || stopped["root_birth"] != held["root_birth"]
        || stopped["operation"] != "export-writer-retired"
        || stopped["sequence"].as_u64() <= held["sequence"].as_u64()
        || stopped["observation"]["pid"] != held["observation"]["pid"]
        || stopped["observation"]["native_wait_completed"] != true
        || stopped["observation"]["raw_wait_status"] != 0
        || stopped["observation"]["native_exit_code"] != 0
        || !stopped["observation"]["native_signal"].is_null()
        || stopped["observation"]["before_root_release"] != true
    {
        return Err("preempty writer actual native stop/wait/phase differs".into());
    }
    closed(
        &owners[0],
        &[
            "pid",
            "birth",
            "parent_pid",
            "parent_birth",
            "retirement_observed",
        ],
    )?;
    if owners[0]["pid"] != native["process_id"]
        || owners[0]["birth"] != native["birth"]
        || owners[0]["parent_pid"] != prepared["target"]["pid"]
        || owners[0]["parent_birth"] != prepared["target"]["birth"]
        || owners[0]["retirement_observed"] != true
    {
        return Err("preempty writer original held child remains live/reassociated".into());
    }
    let mut seen = std::collections::BTreeSet::new();
    for line in custody
        .bytes(&e.stdout)?
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let row = crate::wire::json(line)?;
        if row == held {
            seen.insert("held");
        }
        if row == *stopped {
            seen.insert("stopped");
        }
    }
    if seen.len() != 2 {
        return Err("preempty writer phase records are not actual original stdout".into());
    }
    Ok(())
}
pub(crate) fn validate_export_device(
    e: &LinuxImageExportEvidence,
    prepared: &Value,
    custody: &crate::custody::Custody,
) -> VerificationResult<()> {
    let setup = crate::wire::json(
        custody.bytes(
            e.controller_setup
                .as_deref()
                .ok_or("actual native device creation absent")?,
        )?,
    )?;
    let source = crate::wire::json(custody.bytes(&e.native_source)?)?;
    closed(
        &setup,
        &[
            "format",
            "revision",
            "target_pid",
            "target_birth",
            "root_device",
            "root_inode",
            "work_device",
            "work_inode",
            "path",
            "device",
            "inode",
            "rdev",
            "mode",
            "links",
            "held_live_before_and_after",
        ],
    )?;
    if setup["format"] != "memcordon.linux-native-export-device"
        || setup["revision"] != 1
        || setup["target_pid"] != prepared["target"]["pid"]
        || setup["target_birth"] != prepared["target"]["birth"]
        || setup["root_device"] != prepared["root_device"]
        || setup["root_inode"] != prepared["root_inode"]
        || setup["path"] != "/work/exported.bin"
        || setup["device"] != source["device"]
        || setup["inode"] != source["inode"]
        || setup["mode"] != source["mode"]
        || setup["links"] != 1
        || setup["rdev"] != 259
        || setup["held_live_before_and_after"] != true
        || ["work_device", "work_inode"]
            .iter()
            .any(|field| setup[field].as_u64().is_none_or(|value| value == 0))
    {
        return Err("export unsafe device did not reach actual held prepared root".into());
    }
    let closure_path = e
        .external
        .get("device-admin-handles-retired.json")
        .ok_or("device original controller handles closure absent")?;
    let closure = crate::wire::json(custody.bytes(closure_path)?)?;
    closed(
        &closure,
        &[
            "format",
            "revision",
            "attempt_id",
            "before_root_release",
            "closures",
        ],
    )?;
    if closure["format"] != "memcordon.linux-export-administrative-handle-retirement"
        || closure["revision"] != 1
        || closure["attempt_id"] != prepared["admission"]["attempt_id"]
        || closure["before_root_release"] != true
    {
        return Err("device original owner closure phase/attempt differs".into());
    }
    let owners = closure["closures"]
        .as_array()
        .ok_or("device native controller close records absent")?;
    if owners.len() != 3 {
        return Err("device native root/work/member owner closure incomplete".into());
    }
    for owner in owners {
        closed(owner, &["completed", "errno"])?;
        if owner["completed"] != true || !owner["errno"].is_null() {
            return Err("device controller observation handle remains open".into());
        }
    }
    Ok(())
}
pub(crate) fn validate_export_external_helper(
    e: &LinuxImageExportEvidence,
    owner: &Value,
    checkpoint: &Value,
    prepared: &Value,
    custody: &crate::custody::Custody,
) -> VerificationResult<()> {
    let leaf = |name: &str| -> VerificationResult<&str> {
        e.external
            .get(name)
            .map(String::as_str)
            .ok_or_else(|| "original external export artifact absent".into())
    };
    let decode = |name: &str| crate::wire::json(custody.bytes(leaf(name)?)?);
    let setup = decode("external-helper-setup.json")?;
    let event = decode("external-helper-event.json")?;
    let ack = decode("external-helper-ack.json")?;
    let settled = decode("external-helper-settled.json")?;
    let family_bytes = custody.bytes(leaf("external-family-retirement.json")?)?;
    let cgroup_bytes = custody.bytes(leaf("external-cgroup-retirement.json")?)?;
    validate_linux_export_permission_settlement(
        &setup,
        &event,
        &ack,
        &settled,
        family_bytes,
        cgroup_bytes,
    )?;
    let family = crate::wire::json(family_bytes)?;
    if family["prepared"] != *prepared
        || setup["challenge_hex"] != hex::encode(custody.bytes(&e.challenge)?)
        || setup["work_unix_ms"] != owner["work_deadline_unix_millis"]
        || setup["cleanup_unix_ms"] != owner["cleanup_deadline_unix_millis"]
    {
        return Err(
            "external postempty export crosses original held preparation/challenge/cutoffs".into(),
        );
    }
    let worker = crate::wire::json(custody.bytes(&e.native_worker)?)?;
    if setup["worker"] != worker["worker"] {
        return Err("external postempty event does not join original worker owner".into());
    }
    let source = crate::wire::json(custody.bytes(&e.native_source)?)?;
    for field in [
        "device",
        "inode",
        "uid",
        "gid",
        "length",
        "ctime_seconds",
        "ctime_nanoseconds",
    ] {
        if setup["source"][field] != source[field] {
            return Err("external source differs from original held selected output".into());
        }
    }
    let invocation = decode("external-helper-invocation.json")?;
    let held = decode("external-helper-held.json")?;
    let armed = decode("external-helper-armed.json")?;
    let retired = decode("external-helper-retirement.json")?;
    closed(
        &invocation,
        &[
            "format",
            "revision",
            "program",
            "arguments",
            "cwd",
            "env_clear",
            "executable_sha256",
            "setup_sha256",
        ],
    )?;
    closed(
        &held,
        &[
            "format",
            "revision",
            "process_id",
            "birth",
            "native_image",
            "held_before_setup_delivery",
            "setup_sha256",
            "challenge_hex",
        ],
    )?;
    closed(
        &held["native_image"],
        &["device", "inode", "length", "sha256"],
    )?;
    closed(
        &armed,
        &["format", "revision", "challenge_hex", "source", "worker"],
    )?;
    let program: Vec<u8> =
        serde_json::from_value(invocation["program"].clone()).map_err(|error| error.to_string())?;
    let arguments: Vec<Vec<u8>> = serde_json::from_value(invocation["arguments"].clone())
        .map_err(|error| error.to_string())?;
    let cwd: Vec<u8> =
        serde_json::from_value(invocation["cwd"].clone()).map_err(|error| error.to_string())?;
    let runtime_source = checkpoint["images"]["runtime_source"]
        .as_str()
        .ok_or("original acquired helper source absent")?;
    let fixture = checkpoint["images"]["fixture_sha256"]
        .as_str()
        .ok_or("original acquired helper digest absent")?;
    crate::digest(fixture)?;
    let row = crate::wire::json(custody.bytes(&e.observation)?)?;
    let directory = crate::linux_path::parent(
        row["challenge"]
            .as_str()
            .ok_or("export original challenge native path absent")?,
    )
    .ok_or("export original helper cwd absent")?;
    if invocation["format"] != "memcordon.linux-external-export-helper-invocation"
        || invocation["revision"] != 1
        || program != format!("{runtime_source}/bin/owned-readiness").as_bytes()
        || cwd != directory.as_bytes()
        || invocation["env_clear"] != true
        || invocation["executable_sha256"] != fixture
        || invocation["setup_sha256"] != custody.hash(leaf("external-helper-setup.json")?)?
        || arguments
            != vec![
                b"native-export-permission".to_vec(),
                b"--work-unix-ms".to_vec(),
                owner["work_deadline_unix_millis"].to_string().into_bytes(),
                b"--cleanup-unix-ms".to_vec(),
                owner["cleanup_deadline_unix_millis"]
                    .to_string()
                    .into_bytes(),
            ]
        || held["format"] != "memcordon.linux-external-export-helper-held"
        || held["revision"] != 1
        || held["held_before_setup_delivery"] != true
        || held["setup_sha256"] != invocation["setup_sha256"]
        || held["challenge_hex"] != setup["challenge_hex"]
        || held["native_image"]["sha256"] != fixture
        || held["process_id"]
            .as_u64()
            .is_none_or(|value| value == 0 || value > i32::MAX as u64)
        || held["birth"].as_u64().is_none_or(|value| value == 0)
        || ["device", "inode", "length"].iter().any(|field| {
            held["native_image"][field]
                .as_u64()
                .is_none_or(|value| value == 0)
        })
        || armed["format"] != "memcordon.native-export-permission-armed"
        || armed["revision"] != 1
        || armed["challenge_hex"] != setup["challenge_hex"]
        || armed["source"] != setup["source"]
        || armed["worker"] != setup["worker"]
    {
        return Err("external helper actual command/kernel image/two-FD setup differs".into());
    }
    closed(
        &retired,
        &[
            "format",
            "revision",
            "challenge_hex",
            "process",
            "native_exit",
            "native_success",
            "captures",
            "capture_directory",
            "capture_directory_ancestry",
        ],
    )?;
    closed(
        &retired["process"],
        &[
            "pid",
            "birth",
            "parent_pid",
            "parent_birth",
            "retirement_observed",
        ],
    )?;
    if retired["format"] != "memcordon.linux-external-export-helper-retirement"
        || retired["revision"] != 1
        || retired["challenge_hex"] != setup["challenge_hex"]
        || retired["process"]["pid"] != held["process_id"]
        || retired["process"]["birth"] != held["birth"]
        || retired["process"]["retirement_observed"] != true
        || retired["native_exit"] != 0
        || retired["native_success"] != true
        || retired["capture_directory"] != directory
    {
        return Err("original external helper child wait/held retirement differs".into());
    }
    let captures = retired["captures"]
        .as_array()
        .ok_or("external helper actual capture custody absent")?;
    if captures.len() != 2 {
        return Err("external helper capture closure incomplete".into());
    }
    for (capture, role) in captures.iter().zip(["stdout", "stderr"]) {
        closed(capture, &["role", "device", "inode", "length", "sha256"])?;
        let path = leaf(&format!("external-helper-{role}.bin"))?;
        if capture["role"] != role
            || capture["sha256"] != custody.hash(path)?
            || capture["length"] != custody.bytes(path)?.len()
            || ["device", "inode"]
                .iter()
                .any(|field| capture[field].as_u64().is_none_or(|value| value == 0))
        {
            return Err("external helper actual native capture differs".into());
        }
    }
    if !custody
        .bytes(leaf("external-helper-stderr.bin")?)?
        .is_empty()
    {
        return Err("external helper native stderr is not clean".into());
    }
    let ancestry = retired["capture_directory_ancestry"]
        .as_array()
        .ok_or("external helper protected capture ancestry absent")?;
    if ancestry.is_empty() {
        return Err("external helper capture ancestry empty".into());
    }
    let components = crate::linux_path::ancestors(&directory);
    if ancestry.len() != components.len() {
        return Err("external helper capture ancestry does not cover exact original cwd".into());
    }
    for (ordinal, stamp) in ancestry.iter().enumerate() {
        closed(stamp, &["ordinal", "device", "inode", "uid", "gid", "mode"])?;
        let mode = stamp["mode"]
            .as_u64()
            .ok_or("external capture native mode absent")?;
        let sticky_tmp =
            crate::linux_path::equivalent(&components[components.len() - 1 - ordinal], "/tmp")
                && directory != "/tmp"
                && mode & 0o1000 != 0;
        if stamp["ordinal"] != ordinal
            || stamp["uid"] != 0
            || stamp["gid"].as_u64().is_none()
            || mode & 0o170000 != 0o040000
            || (mode & 0o022 != 0 && !sticky_tmp)
            || ["device", "inode"]
                .iter()
                .any(|field| stamp[field].as_u64().is_none_or(|value| value == 0))
        {
            return Err("external helper capture ancestry lost protected custody".into());
        }
    }
    let closures = decode("external-administrative-closure.json")?;
    let closures = closures
        .as_array()
        .ok_or("external original controller owner closure absent")?;
    if closures.len() != 5 {
        return Err(
            "external original root/work/source/cgroup/parent handle closure incomplete".into(),
        );
    }
    for closure in closures {
        closed(closure, &["completed", "errno"])?;
        if closure["completed"] != true || !closure["errno"].is_null() {
            return Err("external original controller descriptor remains owned".into());
        }
    }
    Ok(())
}
pub(crate) fn validate_export_ready(
    e: &LinuxImageExportEvidence,
    prepared: &Value,
    custody: &crate::custody::Custody,
) -> VerificationResult<()> {
    let ready = crate::wire::json(custody.bytes(&e.ready)?)?;
    let native = crate::wire::json(custody.bytes(&e.prepared_native)?)?;
    closed(
        &ready,
        &[
            "format",
            "revision",
            "sequence",
            "challenge",
            "root_pid",
            "root_birth",
            "operation",
            "observation",
        ],
    )?;
    closed(
        &ready["observation"],
        &["scenario", "path", "kind", "source_path"],
    )?;
    let scenario = e
        .key
        .scenario
        .strip_prefix("export-")
        .ok_or("export scenario prefix absent")?;
    let kind = match scenario {
        "symlink" => "symlink",
        "fifo" => "fifo",
        "socket" => "socket",
        "device" => "admin-device-required",
        "traversal" => "parent-symlink",
        "concurrent-writer" => "regular-with-held-writer",
        _ => return Err("export scenario outside finite set".into()),
    };
    let root_pid = native["target"]["namespace_pids"]
        .as_array()
        .and_then(|pids| pids.last())
        .ok_or("export target namespace PID absent")?;
    if ready["format"] != "memcordon.linux-readiness-transcript"
        || ready["revision"] != 1
        || ready["challenge"] != hex::encode(custody.bytes(&e.challenge)?)
        || ready["root_pid"] != *root_pid
        || ready["root_birth"] != prepared["target"]["birth"]
        || ready["operation"] != "export-object-ready"
        || ready["sequence"].as_u64().is_none_or(|value| value == 0)
        || ready["observation"]["scenario"] != scenario
        || ready["observation"]["kind"] != kind
        || ready["observation"]["path"]
            != if scenario == "traversal" {
                "/work/parent/exported.bin"
            } else {
                "/work/exported.bin"
            }
        || ready["observation"]["source_path"]
            != if scenario == "traversal" {
                serde_json::json!("/work/other/exported.bin")
            } else {
                Value::Null
            }
    {
        return Err("export exact retained readiness/native target differs".into());
    }
    let mut sequence = 0u64;
    let mut matched = 0;
    for line in custody
        .bytes(&e.stdout)?
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let row = crate::wire::json(line)?;
        closed(
            &row,
            &[
                "format",
                "revision",
                "sequence",
                "challenge",
                "root_pid",
                "root_birth",
                "operation",
                "observation",
            ],
        )?;
        let current = row["sequence"]
            .as_u64()
            .ok_or("export raw transcript sequence absent")?;
        if current <= sequence
            || row["format"] != ready["format"]
            || row["revision"] != 1
            || row["challenge"] != ready["challenge"]
            || row["root_pid"] != ready["root_pid"]
            || row["root_birth"] != ready["root_birth"]
        {
            return Err("export raw transcript origin/order differs".into());
        }
        sequence = current;
        if row["operation"] == "export-object-ready" {
            if row != ready {
                return Err("export ready evidence is not original actual stdout frame".into());
            }
            matched += 1;
        }
    }
    if matched != 1 {
        return Err("export original transcript has missing/duplicate readiness".into());
    }
    Ok(())
}
pub(crate) fn validate_export_held_family(
    e: &LinuxImageExportEvidence,
    owner: &Value,
    prepared: &Value,
    attempt: &str,
    product: &crate::ProductObservation,
    custody: &crate::custody::Custody,
) -> VerificationResult<()> {
    let decode = |path: &str| crate::wire::json(custody.bytes(path)?);
    let worker = decode(&e.native_worker)?;
    let family = decode(&e.native_family)?;
    closed(
        &worker,
        &[
            "format",
            "revision",
            "attempt_id",
            "provider",
            "admission",
            "journal_path",
            "journal_device",
            "journal_inode",
            "journal_sha256",
            "journal_bytes",
            "worker",
            "native_image",
        ],
    )?;
    closed(&worker["worker"], &["pid", "birth", "image_sha256"])?;
    closed(
        &worker["native_image"],
        &["device", "inode", "length", "sha256"],
    )?;
    let agent = product
        .components
        .iter()
        .find(|component| component.role == "sealed-agent")
        .ok_or("export selected worker image absent")?;
    let bytes: Vec<u8> = serde_json::from_value(worker["journal_bytes"].clone())
        .map_err(|error| error.to_string())?;
    let journal = crate::linux_recovery_route::decode_journal(&bytes, attempt)?;
    if journal["phase"] != "checkpoint-committed"
        || journal["release_knowledge"] != "not-released"
        || !journal["mixed_export_intent"].is_null()
    {
        return Err("export pre-ACK journal carries later release/export authority".into());
    }
    if worker["format"] != "memcordon.linux-prepared-worker-observation"
        || worker["revision"] != 1
        || worker["attempt_id"] != attempt
        || worker["provider"] != owner["provider"]
        || worker["admission"] != prepared["admission"]
        || worker["journal_path"] != format!("/var/lib/memcordon/sealed/{attempt}")
        || worker["journal_sha256"] != crate::sha256(&bytes)
        || ["journal_device", "journal_inode"]
            .iter()
            .any(|field| worker[field].as_u64().is_none_or(|value| value == 0))
        || journal["mixed_admission_metadata"] != prepared["admission"]
        || journal["mixed_worker"]
            != serde_json::json!({"pid":worker["worker"]["pid"],"start_time":worker["worker"]["birth"]})
        || worker["worker"]["image_sha256"] != agent.installed_sha256
        || worker["native_image"]["sha256"] != agent.installed_sha256
        || ["device", "inode", "length"].iter().any(|field| {
            worker["native_image"][field]
                .as_u64()
                .is_none_or(|value| value == 0)
        })
    {
        return Err("export original native worker journal/kernel image differs".into());
    }
    closed(
        &family,
        &[
            "format",
            "revision",
            "attempt_id",
            "target",
            "namespace_init",
            "guardian",
            "caller",
            "workers",
        ],
    )?;
    if family["format"] != "memcordon.linux-export-held-retirement"
        || family["revision"] != 1
        || family["attempt_id"] != attempt
    {
        return Err("export native held family envelope differs".into());
    }
    let mut identities = std::collections::BTreeSet::new();
    for role in ["target", "namespace_init", "guardian", "caller"] {
        closed(
            &family[role],
            &[
                "pid",
                "birth",
                "parent_pid",
                "parent_birth",
                "retirement_observed",
            ],
        )?;
        let identity: crate::HeldProcessIdentity =
            serde_json::from_value(family[role].clone()).map_err(|error| error.to_string())?;
        if !identity.retirement_observed
            || identity.pid == 0
            || identity.pid > i32::MAX as u32
            || identity.birth == 0
            || family[role]["pid"] != prepared[role]["pid"]
            || family[role]["birth"] != prepared[role]["birth"]
            || !identities.insert((identity.pid, identity.birth))
        {
            return Err("export original held family remains live/reassociated".into());
        }
        if journal[if role == "caller" { "frontend" } else { role }]
            != serde_json::json!({"pid":identity.pid,"start_time":identity.birth})
        {
            return Err("export actual native worker journal family differs".into());
        }
    }
    let workers = family["workers"]
        .as_array()
        .ok_or("export native workers absent")?;
    if workers.len() != 1 {
        return Err("export original native worker owner closure incomplete".into());
    }
    for value in workers {
        closed(
            value,
            &[
                "pid",
                "birth",
                "parent_pid",
                "parent_birth",
                "retirement_observed",
            ],
        )?;
        let identity: crate::HeldProcessIdentity =
            serde_json::from_value(value.clone()).map_err(|error| error.to_string())?;
        if !identity.retirement_observed
            || identity.pid == 0
            || identity.pid > i32::MAX as u32
            || identity.birth == 0
            || value["pid"] != worker["worker"]["pid"]
            || value["birth"] != worker["worker"]["birth"]
            || !identities.insert((identity.pid, identity.birth))
        {
            return Err("export original native worker remains live/reassociated".into());
        }
    }
    Ok(())
}
pub(crate) fn validate_export_recovery(
    e: &LinuxImageExportEvidence,
    owner: &Value,
    prepared: &Value,
    attempt: &str,
    product: &crate::ProductObservation,
    custody: &crate::custody::Custody,
) -> VerificationResult<()> {
    let decode = |path: &str| crate::wire::json(custody.bytes(path)?);
    let recovery = decode(&e.recovery)?;
    closed(
        &recovery,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "lease_id",
            "scenario",
            "attempt_id",
            "original_journal_present",
            "original_journal_sha256",
            "before_paths",
            "after_absence",
            "held_retirement",
            "reservation_before",
            "reservation_after",
            "reservation_parents",
            "invocation",
            "process",
            "stdout",
            "stderr",
            "census",
            "request_sha256",
            "result_sha256",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
    )?;
    if recovery["format"] != "memcordon.linux-export-recovery"
        || recovery["revision"] != 1
        || recovery["identity"] != owner["identity"]
        || recovery["cell"] != owner["cell"]
        || recovery["lease_id"] != e.lease_id
        || recovery["scenario"] != e.key.scenario
        || recovery["attempt_id"] != attempt
        || recovery["request_sha256"] != custody.hash(&e.provider_request)?
        || recovery["result_sha256"] != custody.hash(&e.result)?
        || ["work_deadline_unix_millis", "cleanup_deadline_unix_millis"]
            .iter()
            .any(|field| recovery[field] != owner[field])
    {
        return Err("export recovery crosses original request/source/lifetime".into());
    }
    let artifact = |field: &str| -> VerificationResult<&str> {
        let leaf = recovery[field]
            .as_str()
            .ok_or("export recovery leaf absent")?;
        if leaf.contains('/')
            || leaf
                != format!(
                    "recovery-{field}.{}",
                    if ["stdout", "stderr"].contains(&field) {
                        "bin"
                    } else {
                        "json"
                    }
                )
        {
            return Err("export recovery leaf is not exact original codec".into());
        }
        e.recovery_artifacts
            .get(field)
            .map(String::as_str)
            .ok_or_else(|| "export recovery custody artifact absent".into())
    };
    let invocation = decode(artifact("invocation")?)?;
    let process = decode(artifact("process")?)?;
    if invocation.get("original_fixture").is_some() {
        let proof = &invocation["original_fixture"];
        let references = proof["acquisition_artifacts"]
            .as_object()
            .ok_or("export recovery acquisition references absent")?;
        let mut records = std::collections::BTreeMap::new();
        for (leaf, reference) in references {
            records.insert(
                leaf.clone(),
                custody
                    .bytes(
                        reference
                            .as_str()
                            .ok_or("export recovery acquisition reference malformed")?,
                    )?
                    .to_vec(),
            );
        }
        let input = crate::validate_embedded_original_fixture_recovery(
            &invocation,
            &process,
            &proof["capture"],
            &records,
        )?;
        let recovery_owner_bytes: Vec<u8> = serde_json::from_value(proof["owner_bytes"].clone())
            .map_err(|error| error.to_string())?;
        let recovery_owner = crate::wire::json(&recovery_owner_bytes)?;
        let lease = decode(&e.original_lease_owner)?;
        let admin = lease["admin_root"]
            .as_str()
            .ok_or("export original admin root absent")?;
        if recovery_owner["cell"] != owner["cell"]
            || recovery_owner["owner_path"]
                != crate::linux_path::join(admin, "recovery-harness-owner.json")
            || recovery_owner["executable"]
                != crate::linux_path::join(
                    admin,
                    "recovery-harness/operational/native-test-harness",
                )
        {
            return Err(
                "export recovery harness replaces original installation acquisition".into(),
            );
        }
        let row = decode(&e.observation)?;
        let original_prepared = row["prepared"]
            .as_str()
            .ok_or("export original prepared path absent")?;
        let expected_root = crate::linux_path::parent(original_prepared)
            .ok_or("export original recovery root absent")?;
        if serde_json::to_value(&input.identity).map_err(|error| error.to_string())?
            != owner["identity"]
            || input.scope_id != e.lease_id
            || input.native_target != e.key.target
            || input.original_artifact_root.to_str() != Some(expected_root.as_str())
            || serde_json::json!(input.work_deadline_unix_millis)
                != owner["work_deadline_unix_millis"]
            || serde_json::json!(input.cleanup_deadline_unix_millis)
                != owner["cleanup_deadline_unix_millis"]
        {
            return Err("export fixture recovery crosses original source/lifetime".into());
        }
        match &input.context {
            crate::original_fixture_recovery_contract::Context::Export {
                prepared: record,
                lease_owner,
                original_journal,
                original_reservation,
            } if record.sha256 == custody.hash(&e.prepared)?
                && lease_owner.sha256 == custody.hash(&e.original_lease_owner)?
                && original_journal
                    .as_ref()
                    .map(|record| record.sha256.as_str())
                    == if recovery["original_journal_present"] == true {
                        Some(
                            custody.hash(
                                e.recovery_artifacts
                                    .get("original_journal")
                                    .ok_or("export original journal artifact absent")?,
                            )?,
                        )
                    } else {
                        None
                    } =>
            {
                let reservation_bytes = recovery["reservation_before"]
                    .get("bytes")
                    .map(|bytes| {
                        serde_json::from_value::<Vec<u8>>(bytes.clone())
                            .map_err(|error| error.to_string())
                    })
                    .transpose()?;
                if original_reservation
                    .as_ref()
                    .map(|record| record.sha256.clone())
                    != reservation_bytes
                        .as_ref()
                        .map(|bytes| hex::encode(Sha256::digest(bytes)))
                {
                    return Err("export fixture recovery original reservation differs".into());
                }
            }
            _ => {
                return Err(
                    "export fixture recovery replaces original prepared association".into(),
                );
            }
        }
        if proof["capture"]["stdout"] != serde_json::json!(custody.bytes(artifact("stdout")?)?)
            || proof["capture"]["stderr"] != serde_json::json!(custody.bytes(artifact("stderr")?)?)
        {
            return Err("export fixture recovery raw captures differ".into());
        }
    } else {
        closed(
            &invocation,
            &[
                "format",
                "revision",
                "identity",
                "cell",
                "lease_id",
                "attempt_id",
                "program",
                "arguments",
                "cwd_native_bytes",
                "timeout_millis",
                "cleared_environment",
                "work_deadline_unix_millis",
                "cleanup_deadline_unix_millis",
                "selected_agent_sha256",
            ],
        )?;
        let agent = product
            .components
            .iter()
            .find(|component| component.role == "sealed-agent")
            .ok_or("export recovery installed agent absent")?;
        let row = decode(&e.observation)?;
        let prepared_path = row["prepared"]
            .as_str()
            .ok_or("export original prepared native path absent")?;
        let directory = crate::linux_path::parent(prepared_path)
            .ok_or("export recovery original cwd absent")?;
        let cwd: Vec<u8> = serde_json::from_value(invocation["cwd_native_bytes"].clone())
            .map_err(|error| error.to_string())?;
        if invocation["format"] != "memcordon.linux-export-recovery-invocation"
            || invocation["revision"] != 1
            || invocation["identity"] != owner["identity"]
            || invocation["cell"] != owner["cell"]
            || invocation["lease_id"] != e.lease_id
            || invocation["attempt_id"] != attempt
            || invocation["program"] != "/usr/libexec/memcordon-sealed-agent"
            || invocation["arguments"]
                != serde_json::json!(["package", "policy", "recover", "--json"])
            || cwd != directory.as_bytes()
            || invocation["timeout_millis"] != 60000
            || invocation["cleared_environment"] != true
            || invocation["selected_agent_sha256"] != agent.installed_sha256
            || ["work_deadline_unix_millis", "cleanup_deadline_unix_millis"]
                .iter()
                .any(|field| invocation[field] != owner[field])
        {
            return Err("export recovery actual command/agent/cwd differs".into());
        }
        closed(
            &process,
            &[
                "format",
                "revision",
                "preinput",
                "process",
                "native_image",
                "invocation_sha256",
                "raw_wait_status",
                "native_exit",
                "signal",
                "stdout_sha256",
                "stderr_sha256",
            ],
        )?;
        for field in ["preinput", "process"] {
            closed(
                &process[field],
                &[
                    "pid",
                    "birth",
                    "parent_pid",
                    "parent_birth",
                    "retirement_observed",
                ],
            )?;
        }
        closed(
            &process["native_image"],
            &["device", "inode", "length", "sha256"],
        )?;
        let before: crate::HeldProcessIdentity =
            serde_json::from_value(process["preinput"].clone())
                .map_err(|error| error.to_string())?;
        let after: crate::HeldProcessIdentity = serde_json::from_value(process["process"].clone())
            .map_err(|error| error.to_string())?;
        if before.pid == 0
            || before.pid > i32::MAX as u32
            || before.birth == 0
            || before.retirement_observed
            || !after.retirement_observed
            || before.pid != after.pid
            || before.birth != after.birth
            || before.parent_pid != after.parent_pid
            || before.parent_birth != after.parent_birth
            || process["format"] != "memcordon.linux-export-recovery-process"
            || process["revision"] != 1
            || process["raw_wait_status"] != 0
            || process["native_exit"] != 0
            || !process["signal"].is_null()
            || process["invocation_sha256"] != custody.hash(artifact("invocation")?)?
            || process["stdout_sha256"] != custody.hash(artifact("stdout")?)?
            || process["stderr_sha256"] != custody.hash(artifact("stderr")?)?
            || process["native_image"]["sha256"] != agent.installed_sha256
            || ["device", "inode", "length"].iter().any(|field| {
                process["native_image"][field]
                    .as_u64()
                    .is_none_or(|value| value == 0)
            })
            || !custody.bytes(artifact("stderr")?)?.is_empty()
        {
            return Err("export recovery original child/kernel image/wait/capture differs".into());
        }
        let result = decode(artifact("stdout")?)?;
        closed(&result, &["format", "revision", "outstanding"])?;
        if result["format"] != "memcordon.native-recovery"
            || result["revision"] != 1
            || result["outstanding"] != serde_json::json!([])
        {
            return Err("export native recovery remains outstanding".into());
        }
    }
    let present = recovery["original_journal_present"]
        .as_bool()
        .ok_or("export original journal presence malformed")?;
    if e.recovery_artifacts.len() != if present { 6 } else { 5 }
        || e.recovery_artifacts.keys().any(|key| {
            !matches!(
                key.as_str(),
                "invocation" | "process" | "stdout" | "stderr" | "census" | "original_journal"
            )
        })
    {
        return Err("export recovery custody adds unrelated authority leaves".into());
    }
    let journal = if present {
        let path = e
            .recovery_artifacts
            .get("original_journal")
            .ok_or("export original journal bytes absent")?;
        if recovery["original_journal_sha256"] != custody.hash(path)? {
            return Err("export original journal digest differs".into());
        }
        let journal = crate::linux_recovery_route::decode_journal(custody.bytes(path)?, attempt)?;
        if journal["mixed_admission_metadata"] != prepared["admission"] {
            return Err("export recovery original journal admission differs".into());
        }
        Some(journal)
    } else {
        if !recovery["original_journal_sha256"].is_null()
            || e.recovery_artifacts.contains_key("original_journal")
        {
            return Err("export absent journal has invented bytes".into());
        }
        None
    };
    let reservation = &recovery["reservation_before"];
    let retired_reservation = &recovery["reservation_after"];
    if reservation.get("native_errno").is_some() {
        closed(reservation, &["path", "native_errno"])?;
        closed(retired_reservation, &["path", "native_errno"])?;
        let expected = format!(
            "/var/lib/memcordon/sealed/account-{}-{}-{}.reservation",
            prepared["user_namespace"]["device"],
            prepared["user_namespace"]["inode"],
            owner["account"]["uid"]
        );
        if present
            || reservation["path"] != expected
            || retired_reservation["path"] != expected
            || reservation["native_errno"] != 2
            || retired_reservation["native_errno"] != 2
        {
            return Err(
                "original reservation native absent path differs or retained journal lacks owner"
                    .into(),
            );
        }
    } else {
        closed(
            reservation,
            &["path", "device", "inode", "uid", "mode", "nlink", "bytes"],
        )?;
        closed(
            retired_reservation,
            &[
                "path",
                "device",
                "inode",
                "nlink",
                "native_errno",
                "closed",
                "close_native_errno",
            ],
        )?;
        let bytes: Vec<u8> = serde_json::from_value(reservation["bytes"].clone())
            .map_err(|error| error.to_string())?;
        let body = crate::wire::json(&bytes)?;
        closed(
            &body,
            &[
                "format",
                "revision",
                "user_namespace_device",
                "user_namespace_inode",
                "uid",
                "attempt",
                "owner_pid",
                "owner_birth",
                "boot_identity",
            ],
        )?;
        let original_attempt: Vec<u8> =
            serde_json::from_value(body["attempt"].clone()).map_err(|error| error.to_string())?;
        let worker = crate::wire::json(custody.bytes(&e.native_worker)?)?;
        let path = format!(
            "/var/lib/memcordon/sealed/account-{}-{}-{}.reservation",
            body["user_namespace_device"], body["user_namespace_inode"], body["uid"]
        );
        let mode = reservation["mode"]
            .as_u64()
            .ok_or("reservation native mode absent")?;
        if body["format"] != "memcordon.account-reservation"
            || body["revision"] != 1
            || hex::encode(original_attempt) != attempt
            || body["uid"] != owner["account"]["uid"]
            || body["user_namespace_device"] != prepared["user_namespace"]["device"]
            || body["user_namespace_inode"] != prepared["user_namespace"]["inode"]
            || body["owner_pid"] != worker["worker"]["pid"]
            || body["owner_birth"] != worker["worker"]["birth"]
            || body["boot_identity"].as_str().is_none_or(str::is_empty)
            || journal
                .as_ref()
                .is_some_and(|journal| journal["boot_identity"] != body["boot_identity"])
            || reservation["path"] != path
            || reservation["uid"] != 0
            || mode & 0o170000 != 0o100000
            || mode & 0o7777 != 0o600
            || reservation["nlink"] != 1
            || ["device", "inode"]
                .iter()
                .any(|field| reservation[field].as_u64().is_none_or(|value| value == 0))
            || retired_reservation["path"] != reservation["path"]
            || retired_reservation["device"] != reservation["device"]
            || retired_reservation["inode"] != reservation["inode"]
            || retired_reservation["nlink"] != 0
            || retired_reservation["native_errno"] != 2
            || retired_reservation["closed"] != true
            || !retired_reservation["close_native_errno"].is_null()
        {
            return Err(
                "original exclusive account reservation owner/native retirement differs".into(),
            );
        }
    }
    let parents = recovery["reservation_parents"]
        .as_array()
        .ok_or("original reservation protected ancestry absent")?;
    let names = [
        "/",
        "/var",
        "/var/lib",
        "/var/lib/memcordon",
        "/var/lib/memcordon/sealed",
    ];
    if parents.len() != names.len() {
        return Err("original reservation protected ancestry incomplete".into());
    }
    for (parent, path) in parents.iter().zip(names) {
        closed(
            parent,
            &[
                "path",
                "device",
                "inode",
                "uid",
                "mode",
                "nlink",
                "named_device",
                "named_inode",
                "closed",
                "close_native_errno",
            ],
        )?;
        let mode = parent["mode"]
            .as_u64()
            .ok_or("reservation parent native mode absent")?;
        if parent["path"] != path
            || parent["uid"] != 0
            || mode & 0o170000 != 0o040000
            || mode & 0o022 != 0
            || parent["device"] != parent["named_device"]
            || parent["inode"] != parent["named_inode"]
            || ["device", "inode", "nlink"]
                .iter()
                .any(|field| parent[field].as_u64().is_none_or(|value| value == 0))
            || parent["closed"] != true
            || !parent["close_native_errno"].is_null()
        {
            return Err(
                "original reservation parent identity/readback/native closure differs".into(),
            );
        }
    }
    let paths = recovery["before_paths"]
        .as_array()
        .ok_or("export original allocations absent")?;
    let absence = recovery["after_absence"]
        .as_array()
        .ok_or("export allocation named absence absent")?;
    let retired = recovery["held_retirement"]
        .as_array()
        .ok_or("export allocation held retirement absent")?;
    let mut expected_retired = std::collections::BTreeMap::new();
    let mut seen = std::collections::BTreeSet::new();
    for path in paths {
        let field = path["field"]
            .as_str()
            .ok_or("export allocation field absent")?;
        let identity = match field {
            "mixed_root_staging_intent" => "mixed_staging_identity",
            "mixed_export_intent" => "mixed_export_identity",
            _ => return Err("export recovery added unrelated allocation".into()),
        };
        let original = journal
            .as_ref()
            .ok_or("export allocations lack original native journal")?;
        let name = path["path"]
            .as_str()
            .ok_or("export allocation path absent")?;
        if !seen.insert(field) || path["path"] != original[field] {
            return Err("export original allocation path differs/duplicates".into());
        }
        if path.get("native_errno").is_some() {
            closed(path, &["field", "path", "native_errno"])?;
            if path["native_errno"] != 2 {
                return Err("export allocation absence is not ENOENT".into());
            }
        } else {
            closed(path, &["field", "path", "device", "inode", "uid", "mode"])?;
            let mode = path["mode"]
                .as_u64()
                .ok_or("export allocation native mode absent")?;
            if path["device"] != original[identity]["device"]
                || path["inode"] != original[identity]["inode"]
                || path["uid"] != 0
                || mode & 0o170000 != 0o040000
                || mode & 0o022 != 0
                || ["device", "inode"]
                    .iter()
                    .any(|field| path[field].as_u64().is_none_or(|value| value == 0))
            {
                return Err("export original held directory identity/custody differs".into());
            }
            expected_retired.insert(name.to_owned(), path);
        }
    }
    let declared = journal
        .as_ref()
        .map(|journal| {
            ["mixed_root_staging_intent", "mixed_export_intent"]
                .into_iter()
                .filter(|field| journal[*field].as_str().is_some())
                .collect::<std::collections::BTreeSet<_>>()
        })
        .unwrap_or_default();
    if seen != declared || absence.len() != paths.len() || retired.len() != expected_retired.len() {
        return Err("export native directory closure is incomplete".into());
    }
    let mut absent = std::collections::BTreeSet::new();
    for item in absence {
        closed(item, &["path", "native_errno"])?;
        let name = item["path"]
            .as_str()
            .ok_or("export named absence path absent")?;
        if item["native_errno"] != 2
            || !absent.insert(name)
            || !paths.iter().any(|path| path["path"] == name)
        {
            return Err("export original named removal differs/duplicates".into());
        }
    }
    for item in retired {
        closed(
            item,
            &[
                "path",
                "device",
                "inode",
                "nlink",
                "close_native_errno",
                "closed",
            ],
        )?;
        let name = item["path"]
            .as_str()
            .ok_or("export held retirement path absent")?;
        let original = expected_retired
            .remove(name)
            .ok_or("export held retirement owner differs/duplicates")?;
        if item["device"] != original["device"]
            || item["inode"] != original["inode"]
            || item["nlink"] != 0
            || item["closed"] != true
            || !item["close_native_errno"].is_null()
        {
            return Err("export original directory owner remains live or linked".into());
        }
    }
    let census = decode(artifact("census")?)?;
    let journal_parent = parents
        .last()
        .ok_or("original reservation journal parent absent")?;
    if ["device", "inode"]
        .iter()
        .any(|field| journal_parent[*field] != census["journal_root"][*field])
    {
        return Err(
            "export reservation parent differs from original post-recovery native journal census"
                .into(),
        );
    }
    crate::validate_linux_refusal_census(
        &census,
        &owner["identity"],
        &owner["cell"],
        &e.lease_id,
        &e.key.scenario,
        &owner["account"],
        &owner["provider"],
        custody.hash(&e.provider_request)?,
        custody.hash(&e.result)?,
        attempt,
    )?;
    Ok(())
}
/// A fixture's type label cannot replace actual held native file metadata.
pub fn validate_linux_export_source(
    scenario: &str,
    source: &Value,
    prepared: &Value,
    account: &Value,
) -> VerificationResult<()> {
    closed(
        source,
        &[
            "format",
            "revision",
            "scenario",
            "attempt_id",
            "target",
            "root_device",
            "root_inode",
            "member",
            "device",
            "inode",
            "mode",
            "uid",
            "gid",
            "nlink",
            "length",
            "ctime_seconds",
            "ctime_nanoseconds",
            "symlink_target",
            "exclusive_uid",
            "exclusive_gid",
        ],
    )?;
    if source["format"] != "memcordon.linux-export-native-source"
        || source["revision"] != 1
        || source["scenario"] != scenario
        || source["attempt_id"] != prepared["attempt_id"]
        || source["target"] != prepared["target"]
        || source["root_device"] != prepared["root_device"]
        || source["root_inode"] != prepared["root_inode"]
        || source["exclusive_uid"] != account["uid"]
        || source["exclusive_gid"] != account["gid"]
        || source["uid"]
            != if scenario == "device" {
                serde_json::json!(0)
            } else {
                account["uid"].clone()
            }
        || source["gid"]
            != if scenario == "device" {
                serde_json::json!(0)
            } else {
                account["gid"].clone()
            }
        || ["device", "inode", "nlink"]
            .iter()
            .any(|field| source[field].as_u64().is_none_or(|value| value == 0))
        || source["nlink"] != 1
        || source["length"].as_u64().is_none()
        || source["ctime_seconds"].as_i64().is_none()
        || source["ctime_nanoseconds"]
            .as_u64()
            .is_none_or(|value| value >= 1_000_000_000)
    {
        return Err("export native object crosses original root/identity".into());
    }
    let mode = source["mode"]
        .as_u64()
        .filter(|mode| *mode <= u32::MAX as u64)
        .ok_or("export native object mode absent")?;
    let kind = mode & 0o170000;
    let expected = match scenario {
        "symlink" | "traversal" => 0o120000,
        "fifo" => 0o010000,
        "device" => 0o020000,
        "socket" => 0o140000,
        "concurrent-writer" => 0o100000,
        _ => return Err("unfrozen export native source scenario".into()),
    };
    if kind != expected
        || source["member"]
            != if scenario == "traversal" {
                "parent"
            } else {
                "exported.bin"
            }
        || (scenario == "traversal" && source["symlink_target"] != "/work/other")
        || (scenario == "symlink" && source["symlink_target"] != "/owned-source/Cargo.toml")
        || (!matches!(scenario, "symlink" | "traversal") && !source["symlink_target"].is_null())
    {
        return Err("actual export native type/path differs from selected hostile object".into());
    }
    Ok(())
}

/// Export failure is an authorized indeterminate terminal, never an Executed retirement.
pub fn validate_linux_export_outcome(
    scenario: &str,
    result: &Value,
    attempt: &str,
    request_digest: &str,
    native_status: i32,
) -> VerificationResult<String> {
    closed(
        result,
        &[
            "format",
            "revision",
            "tool",
            "invocation",
            "runtime",
            "delivery",
            "frontend",
            "wrapper_status",
        ],
    )?;
    let runtime = &result["runtime"];
    closed(
        runtime,
        &[
            "kind",
            "carrier_revision",
            "provider_contract",
            "launch_wire",
            "outcome",
        ],
    )?;
    let outcome = &runtime["outcome"];
    closed(
        outcome,
        &[
            "kind",
            "attempt_id",
            "request_sha256",
            "retained_obligations",
        ],
    )?;
    let obligations = &outcome["retained_obligations"];
    closed(obligations, &["authorization", "obligations"])?;
    closed(
        &result["frontend"],
        &["relay_drained", "interruption", "relay_error"],
    )?;
    if result["format"] != "memcordon.result"
        || result["revision"] != 2
        || result["wrapper_status"] != native_status
        || runtime["kind"] != "linux-mixed-private"
        || runtime["carrier_revision"] != 2
        || runtime["provider_contract"] != 4
        || runtime["launch_wire"] != 4
        || native_status <= 0
        || native_status > 255
        || outcome["kind"] != "indeterminate"
        || outcome["attempt_id"] != attempt
        || outcome["request_sha256"] != request_digest
        || obligations["authorization"] != "authorized"
        || result["frontend"]["relay_drained"] != true
        || !result["frontend"]["interruption"].is_null()
        || !result["frontend"]["relay_error"].is_null()
    {
        return Err("export refusal original authorized terminal differs".into());
    }
    let details = obligations["obligations"]
        .as_array()
        .ok_or("export native first cause absent")?;
    if details.len() != 1 {
        return Err("export refusal has unrelated or missing original native obligations".into());
    }
    let detail = details[0]
        .as_str()
        .filter(|value| !value.is_empty() && value.len() <= 256)
        .ok_or("export native original cause invalid")?;
    let accepted = match scenario {
        "symlink" | "traversal" => detail == "Too many levels of symbolic links (os error 40)",
        "fifo" | "device" => detail == "selected output lacks exclusive regular-file custody",
        "socket" => detail == "No such device or address (os error 6)",
        "concurrent-writer" => [
            "selected output changed during copy",
            "selected output native identity/content changed",
        ]
        .contains(&detail),
        _ => false,
    };
    if !accepted {
        return Err(
            "export refusal native original cause does not match actual source effect".into(),
        );
    }
    Ok(detail.into())
}

pub fn validate_linux_export_permission_settlement(
    setup: &Value,
    event: &Value,
    ack: &Value,
    settled: &Value,
    family_bytes: &[u8],
    cgroup_bytes: &[u8],
) -> VerificationResult<()> {
    closed(
        setup,
        &[
            "format",
            "revision",
            "challenge_hex",
            "work_unix_ms",
            "cleanup_unix_ms",
            "source",
            "cgroup",
            "worker",
        ],
    )?;
    closed(
        event,
        &[
            "format",
            "revision",
            "event_id",
            "challenge_hex",
            "source",
            "worker",
            "cgroup_retirement",
        ],
    )?;
    closed(
        ack,
        &[
            "format",
            "revision",
            "event_id",
            "challenge_hex",
            "source_device",
            "source_inode",
            "worker_pid",
            "worker_birth",
            "family_retirement_sha256",
            "cgroup_retirement_sha256",
            "retirement_kind",
        ],
    )?;
    closed(
        settled,
        &[
            "format",
            "revision",
            "challenge_hex",
            "work_unix_ms",
            "cleanup_unix_ms",
            "permission_answer",
            "mark_installed",
            "unmark",
            "closures",
            "operation",
            "operation_error",
            "settlement_errors",
        ],
    )?;
    closed(
        &settled["permission_answer"],
        &["attempted", "fan_allow_written"],
    )?;
    closed(&settled["unmark"], &["attempted", "completed", "errno"])?;
    let operation = &settled["operation"];
    closed(
        operation,
        &[
            "event_id",
            "before_length",
            "after_length",
            "before_ctime_seconds",
            "before_ctime_nanoseconds",
            "after_ctime_seconds",
            "after_ctime_nanoseconds",
            "family_retirement_sha256",
            "cgroup_retirement_sha256",
            "cgroup_retirement",
        ],
    )?;
    closed(
        &event["source"],
        &[
            "device",
            "inode",
            "uid",
            "gid",
            "length",
            "ctime_seconds",
            "ctime_nanoseconds",
        ],
    )?;
    closed(&event["worker"], &["pid", "birth", "image_sha256"])?;
    closed(
        &event["cgroup_retirement"],
        &["device", "inode", "native_links", "filesystem", "kind"],
    )?;
    let family: Value = crate::wire::decode(family_bytes)?;
    closed(
        &family,
        &[
            "format",
            "revision",
            "prepared",
            "challenge_hex",
            "target",
            "namespace_init",
            "guardian",
        ],
    )?;
    let cgroup: Value = crate::wire::decode(cgroup_bytes)?;
    closed(
        &cgroup,
        &[
            "format",
            "revision",
            "attempt_id",
            "prepared",
            "held",
            "parent",
            "named_attempt_errno",
        ],
    )?;
    closed(
        &cgroup["parent"],
        &["path", "device", "inode", "uid", "mode"],
    )?;
    let digest = |value: &Value| {
        value.as_str().is_some_and(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    };
    if !digest(&event["event_id"])
        || !digest(&event["challenge_hex"])
        || event["challenge_hex"] == "0".repeat(64)
        || !digest(&event["worker"]["image_sha256"])
        || event["worker"]["pid"]
            .as_u64()
            .is_none_or(|value| value == 0 || value > i32::MAX as u64)
        || event["worker"]["birth"]
            .as_u64()
            .is_none_or(|value| value == 0)
        || ["device", "inode"].iter().any(|field| {
            event["source"][field]
                .as_u64()
                .is_none_or(|value| value == 0)
                || event["cgroup_retirement"][field]
                    .as_u64()
                    .is_none_or(|value| value == 0)
                || cgroup["parent"][field]
                    .as_u64()
                    .is_none_or(|value| value == 0)
        })
        || ["uid", "gid"].iter().any(|field| {
            event["source"][field]
                .as_u64()
                .is_none_or(|value| value > u32::MAX as u64)
        })
        || setup["work_unix_ms"]
            .as_u64()
            .is_none_or(|value| value == 0)
        || setup["cleanup_unix_ms"].as_u64() <= setup["work_unix_ms"].as_u64()
    {
        return Err("native export event identities/deadlines absent or invalid".into());
    }
    if setup["format"] != "memcordon.native-export-permission-setup"
        || event["format"] != "memcordon.native-export-permission-event"
        || ack["format"] != "memcordon.native-export-permission-ack"
        || settled["format"] != "memcordon.native-export-permission-settled"
        || family["format"] != "memcordon.linux-export-native-family-retirement"
        || cgroup["format"] != "memcordon.linux-export-native-cgroup-retirement"
        || [setup, event, ack, settled, &family, &cgroup]
            .iter()
            .any(|value| value["revision"] != 1)
        || event["challenge_hex"] != setup["challenge_hex"]
        || event["source"] != setup["source"]
        || event["worker"] != setup["worker"]
        || ack["event_id"] != event["event_id"]
        || ack["challenge_hex"] != event["challenge_hex"]
        || ack["source_device"] != event["source"]["device"]
        || ack["source_inode"] != event["source"]["inode"]
        || ack["worker_pid"] != event["worker"]["pid"]
        || ack["worker_birth"] != event["worker"]["birth"]
        || ack["family_retirement_sha256"] != crate::sha256(family_bytes)
        || ack["cgroup_retirement_sha256"] != crate::sha256(cgroup_bytes)
        || ack["retirement_kind"] != "removed-held-inode"
        || family["challenge_hex"] != event["challenge_hex"]
        || cgroup["prepared"] != family["prepared"]
        || cgroup["attempt_id"] != family["prepared"]["admission"]["attempt_id"]
        || cgroup["held"] != event["cgroup_retirement"]
        || cgroup["named_attempt_errno"] != 2
        || cgroup["parent"]["path"] != "/sys/fs/cgroup/memcordon-sealed"
        || cgroup["parent"]["uid"] != 0
        || cgroup["parent"]["mode"]
            .as_u64()
            .is_none_or(|mode| mode & 0o170000 != 0o040000 || mode & 0o022 != 0)
        || event["cgroup_retirement"]["filesystem"] != "cgroup2"
        || event["cgroup_retirement"]["kind"] != "removed-held-inode"
        || event["cgroup_retirement"]["native_links"] != 0
        || event["cgroup_retirement"]["device"] != setup["cgroup"]["device"]
        || event["cgroup_retirement"]["inode"] != setup["cgroup"]["inode"]
    {
        return Err(
            "post-empty export permission event/recovery ACK native ownership differs".into(),
        );
    }
    let mut held_identities = std::collections::BTreeSet::new();
    for role in ["target", "namespace_init", "guardian"] {
        let held = &family[role];
        closed(
            held,
            &[
                "pid",
                "birth",
                "parent_pid",
                "parent_birth",
                "retirement_observed",
            ],
        )?;
        let pid = held["pid"]
            .as_u64()
            .filter(|value| *value > 0 && *value <= i32::MAX as u64)
            .ok_or("native export family PID invalid")?;
        let birth = held["birth"]
            .as_u64()
            .filter(|value| *value > 0)
            .ok_or("native export family birth invalid")?;
        if !held_identities.insert((pid, birth))
            || held["retirement_observed"] != true
            || held["pid"] != family["prepared"][role]["pid"]
            || held["birth"] != family["prepared"][role]["birth"]
        {
            return Err(
                "post-empty export event precedes actual original native family retirement".into(),
            );
        }
    }
    if settled["challenge_hex"] != event["challenge_hex"]
        || settled["work_unix_ms"] != setup["work_unix_ms"]
        || settled["cleanup_unix_ms"] != setup["cleanup_unix_ms"]
        || settled["mark_installed"] != true
        || settled["permission_answer"]["attempted"] != true
        || settled["permission_answer"]["fan_allow_written"] != true
        || settled["unmark"]["attempted"] != true
        || settled["unmark"]["completed"] != true
        || !settled["unmark"]["errno"].is_null()
        || operation["event_id"] != event["event_id"]
        || operation["before_length"] != event["source"]["length"]
        || operation["after_length"].as_u64()
            != event["source"]["length"]
                .as_u64()
                .and_then(|value| value.checked_add(32))
        || operation["before_ctime_seconds"] != event["source"]["ctime_seconds"]
        || operation["before_ctime_nanoseconds"] != event["source"]["ctime_nanoseconds"]
        || operation["after_ctime_seconds"].as_i64().is_none()
        || operation["after_ctime_nanoseconds"]
            .as_u64()
            .is_none_or(|value| value >= 1_000_000_000)
        || operation["family_retirement_sha256"] != ack["family_retirement_sha256"]
        || operation["cgroup_retirement_sha256"] != ack["cgroup_retirement_sha256"]
        || operation["cgroup_retirement"] != event["cgroup_retirement"]
        || !settled["operation_error"].is_null()
        || settled["settlement_errors"]
            .as_array()
            .is_none_or(|errors| !errors.is_empty())
    {
        return Err("post-empty export mutation/permission settlement differs".into());
    }
    let closures = settled["closures"]
        .as_array()
        .ok_or("native export permission closures absent")?;
    let roles = [
        "event",
        "event-pidfd",
        "worker-pidfd",
        "group",
        "source",
        "cgroup",
    ];
    if closures.len() != roles.len() {
        return Err("native export permission owner closures omitted".into());
    }
    for (closure, role) in closures.iter().zip(roles) {
        closed(closure, &["role", "attempted", "completed", "errno"])?;
        if closure["role"] != role
            || closure["attempted"] != true
            || closure["completed"] != true
            || !closure["errno"].is_null()
        {
            return Err("native export permission closure order/effect differs".into());
        }
    }
    Ok(())
}
