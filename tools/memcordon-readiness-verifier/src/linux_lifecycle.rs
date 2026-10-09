//! Lifecycle losses retain their original raw native graph, including the
//! absence of a result when the owned frontend was killed.
use crate::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxLifecycleLossEvidence {
    pub format: String,
    pub revision: u32,
    pub key: CaseKey,
    pub run_id: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub lease_id: String,
    pub fixture: String,
    pub fixture_sha256: String,
    pub fixture_source: String,
    pub fixture_source_sha256: String,
    pub input: String,
    pub owner: String,
    pub raw: String,
    pub artifacts: Vec<BehaviorArtifact>,
}

/// Delivery failures use the same custody envelope and a separate format and
/// finite decoder, retaining the actual authenticated carrier independently.
pub type LinuxDeliveryEvidence = LinuxLifecycleLossEvidence;

fn closed(value: &Value, fields: &[&str]) -> VerificationResult<()> {
    if value.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|field| !fields.contains(&field.as_str()))
    }) {
        return Err("lifecycle raw native schema differs".into());
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "Compare independent lifecycle identity, cell, worker, intent and native retirement evidence"
)]
pub fn validate_linux_lifecycle_intervention(
    key: &CaseKey,
    intent: &Value,
    action: &Value,
    prepared: &Value,
    worker: &Value,
    journal_bytes: &[u8],
    identity: &Value,
    cell: &Value,
    lease_id: &str,
    cli_sha256: &str,
    agent_sha256: &str,
) -> VerificationResult<()> {
    let (actor, phase) = key
        .scenario
        .split_once('-')
        .ok_or("lifecycle finite actor/phase absent")?;
    if key.family != "L-LIFE-02"
        || !["frontend", "worker", "guardian", "control"].contains(&actor)
        || !["allocation", "release", "drain"].contains(&phase)
    {
        return Err("lifecycle intervention outside finite twelve".into());
    }
    closed(
        intent,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "lease_id",
            "key",
            "attempt_id",
            "actor",
            "phase",
            "release_knowledge",
            "journal_sha256",
            "release_barrier",
            "native_image",
            "selected_image_sha256",
            "native_operation",
        ],
    )?;
    let attempt = prepared["admission"]["attempt_id"]
        .as_str()
        .ok_or("lifecycle original admitted attempt absent")?;
    let journal = crate::linux_recovery_route::decode_journal(journal_bytes, attempt)?;
    let expected_phase = if phase == "drain" {
        "retiring"
    } else {
        "checkpoint-committed"
    };
    let knowledge = if phase == "drain" {
        "exec-observed"
    } else {
        "not-released"
    };
    let journal_actor = match actor {
        "frontend" => "frontend",
        "guardian" => "guardian",
        _ => "mixed_worker",
    };
    let original_actor = if actor == "frontend" {
        &prepared["caller"]
    } else if actor == "guardian" {
        &prepared["guardian"]
    } else {
        worker
    };
    let selected: HeldProcessIdentity =
        serde_json::from_value(intent["actor"].clone()).map_err(|error| error.to_string())?;
    let selected_image = if actor == "frontend" {
        cli_sha256
    } else {
        agent_sha256
    };
    closed(
        &intent["native_image"],
        &["device", "inode", "length", "sha256"],
    )?;
    if intent["format"] != "memcordon.linux-lifecycle-controller-intent"
        || intent["revision"] != 1
        || intent["identity"] != *identity
        || intent["cell"] != *cell
        || intent["lease_id"] != lease_id
        || intent["key"] != serde_json::to_value(key).map_err(|error| error.to_string())?
        || intent["attempt_id"] != attempt
        || intent["journal_sha256"] != sha256(journal_bytes)
        || intent["phase"] != expected_phase
        || journal["phase"] != expected_phase
        || intent["release_knowledge"] != knowledge
        || journal["release_knowledge"] != knowledge
        || selected.retirement_observed
        || selected.pid == 0
        || selected.pid > i32::MAX as u32
        || selected.birth == 0
        || journal[journal_actor]["pid"] != selected.pid
        || journal[journal_actor]["start_time"] != selected.birth
        || original_actor["pid"] != selected.pid
        || original_actor["birth"] != selected.birth
        || intent["selected_image_sha256"] != selected_image
        || intent["native_image"]["sha256"] != selected_image
        || ["device", "inode", "length"].iter().any(|field| {
            intent["native_image"][*field]
                .as_u64()
                .is_none_or(|number| number == 0)
        })
    {
        return Err("lifecycle intervention replaces original native actor/source/phase".into());
    }
    if actor == "control" {
        closed(
            action,
            &[
                "format",
                "revision",
                "worker",
                "caller",
                "source_descriptor",
                "device",
                "inode",
                "peer_uid",
                "peer_gid",
                "socket_type",
                "socket_domain",
                "caller_status_bytes",
                "native_how",
                "native_status",
                "native_errno",
            ],
        )?;
        closed(&action["worker"], &["pid", "birth"])?;
        closed(&action["caller"], &["pid", "birth"])?;
        if intent["native_operation"] != "socket-shutdown"
            || action["format"] != "memcordon.linux-lifecycle-control-shutdown"
            || action["revision"] != 1
            || action["worker"]["pid"] != selected.pid
            || action["worker"]["birth"] != selected.birth
            || action["caller"]["pid"] != prepared["caller"]["pid"]
            || action["caller"]["birth"] != prepared["caller"]["birth"]
            || action["source_descriptor"]
                .as_u64()
                .is_none_or(|number| number > i32::MAX as u64)
            || action["peer_uid"] != 65534
            || action["peer_gid"] != 65534
            || prepared["admission"]["caller_uid"] != 65534
            || ["device", "inode"]
                .iter()
                .any(|field| action[*field].as_u64().is_none_or(|number| number == 0))
            || action["socket_type"] != 1
            || action["socket_domain"] != 1
            || action["native_how"] != 2
        {
            return Err(
                "lifecycle control loss lacks actual original connected native socket shutdown"
                    .into(),
            );
        }
        let status: Vec<u8> = serde_json::from_value(action["caller_status_bytes"].clone())
            .map_err(|error| error.to_string())?;
        if status.is_empty() || status.len() > 65536 {
            return Err("lifecycle native caller credential source bound differs".into());
        }
        let status = std::str::from_utf8(&status).map_err(|error| error.to_string())?;
        for (field, selected) in [("Uid:", &action["peer_uid"]), ("Gid:", &action["peer_gid"])] {
            let uid = selected
                .as_u64()
                .filter(|value| *value > 0 && *value <= u32::MAX as u64)
                .ok_or("lifecycle control native unprivileged caller absent")?;
            let values = status
                .lines()
                .find_map(|line| line.strip_prefix(field))
                .ok_or("lifecycle native caller credential line absent")?
                .split_whitespace()
                .map(str::parse::<u64>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| error.to_string())?;
            if values != vec![uid; 4] {
                return Err(
                    "lifecycle native control peer differs from original caller credential source"
                        .into(),
                );
            }
        }
    } else {
        closed(
            action,
            &[
                "format",
                "revision",
                "actor",
                "signal",
                "native_status",
                "native_errno",
            ],
        )?;
        if intent["native_operation"] != "pidfd-sigkill"
            || action["format"] != "memcordon.linux-lifecycle-pidfd-kill"
            || action["revision"] != 1
            || action["actor"] != intent["actor"]
            || action["signal"] != 9
        {
            return Err("lifecycle loss lacks original held native PIDFD SIGKILL".into());
        }
    }
    if action["native_status"] != 0 || !action["native_errno"].is_null() {
        return Err("lifecycle native intervention did not succeed".into());
    }
    if phase == "release" {
        let barrier: &Value = &intent["release_barrier"];
        closed(
            barrier,
            &["format", "revision", "prepared", "authorizes_launch"],
        )?;
        if barrier["format"] != "memcordon.mixed-release-observation"
            || barrier["revision"] != 2
            || barrier["prepared"] != *prepared
            || barrier["authorizes_launch"] != false
        {
            return Err("lifecycle release intervention lacks actual unauthorizing barrier".into());
        }
    } else if !intent["release_barrier"].is_null() {
        return Err("lifecycle phase adopts another release barrier".into());
    }
    Ok(())
}

impl LinuxLifecycleLossEvidence {
    pub(crate) fn artifact_paths(&self) -> Vec<&str> {
        let mut paths = vec![
            self.fixture.as_str(),
            self.fixture_source.as_str(),
            self.input.as_str(),
            self.owner.as_str(),
            self.raw.as_str(),
        ];
        paths.extend(self.artifacts.iter().map(|artifact| artifact.path.as_str()));
        paths
    }
}

/// Check the original held family after recovery, independently of whether the
/// interrupted frontend managed to publish a result.
#[expect(
    clippy::too_many_arguments,
    reason = "Compare independent lifecycle identity, cell, worker, intent and native retirement evidence"
)]
pub fn validate_linux_lifecycle_family_settlement(
    raw: &Value,
    prepared: &Value,
    worker: &Value,
    intent: &Value,
    identity: &Value,
    cell: &Value,
    lease_id: &str,
    key: &CaseKey,
) -> VerificationResult<()> {
    closed(
        raw,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "lease_id",
            "key",
            "attempt_id",
            "frontend",
            "target",
            "namespace_init",
            "guardian",
            "worker",
            "actor",
            "descendants",
            "transcript",
        ],
    )?;
    if raw["format"] != "memcordon.linux-lifecycle-native-family-retirement"
        || raw["revision"] != 1
        || raw["identity"] != *identity
        || raw["cell"] != *cell
        || raw["lease_id"] != lease_id
        || raw["key"] != serde_json::to_value(key).map_err(|error| error.to_string())?
        || raw["attempt_id"] != prepared["admission"]["attempt_id"]
    {
        return Err("lifecycle native family settlement crosses original attempt/lease".into());
    }
    let mut original = BTreeMap::new();
    for (field, before) in [
        ("frontend", &prepared["caller"]),
        ("target", &prepared["target"]),
        ("namespace_init", &prepared["namespace_init"]),
        ("guardian", &prepared["guardian"]),
        ("worker", worker),
    ] {
        let held: HeldProcessIdentity =
            serde_json::from_value(raw[field].clone()).map_err(|error| error.to_string())?;
        if held.pid == 0
            || held.pid > i32::MAX as u32
            || held.birth == 0
            || !held.retirement_observed
            || before["pid"] != held.pid
            || before["birth"] != held.birth
            || original.insert((held.pid, held.birth), field).is_some()
        {
            return Err(
                "lifecycle retirement substitutes or repeats original held native owner".into(),
            );
        }
    }
    let actor: HeldProcessIdentity =
        serde_json::from_value(raw["actor"].clone()).map_err(|error| error.to_string())?;
    if !actor.retirement_observed
        || intent["actor"]["pid"] != actor.pid
        || intent["actor"]["birth"] != actor.birth
        || !original.contains_key(&(actor.pid, actor.birth))
    {
        return Err(
            "lifecycle controller actor is not an originally held retired family member".into(),
        );
    }
    let descendants = raw["descendants"]
        .as_array()
        .ok_or("lifecycle descendant native settlement absent")?;
    if descendants.len() > 1024 {
        return Err("lifecycle native descendant settlement exceeds bound".into());
    }
    let mut namespace_pids = BTreeSet::new();
    let mut descendants_by_identity = BTreeMap::new();
    for entry in descendants {
        closed(entry, &["identity", "namespace_pid"])?;
        let held: HeldProcessIdentity =
            serde_json::from_value(entry["identity"].clone()).map_err(|error| error.to_string())?;
        let namespace = entry["namespace_pid"]
            .as_u64()
            .filter(|pid| *pid > 0 && *pid <= i32::MAX as u64)
            .ok_or("lifecycle original descendant namespace PID absent")?;
        if held.pid == 0
            || held.pid > i32::MAX as u32
            || held.birth == 0
            || !held.retirement_observed
            || held
                .parent_pid
                .is_none_or(|pid| pid == 0 || pid > i32::MAX as u32)
            || held.parent_birth.is_none_or(|birth| birth == 0)
            || original.contains_key(&(held.pid, held.birth))
            || !namespace_pids.insert(namespace)
            || descendants_by_identity
                .insert((held.pid, held.birth), held)
                .is_some()
        {
            return Err(
                "lifecycle descendant settlement substitutes identity/namespace/ancestry".into(),
            );
        }
    }
    for descendant in descendants_by_identity.values() {
        let mut current = descendant;
        let mut visited = BTreeSet::new();
        loop {
            if !visited.insert((current.pid, current.birth)) || visited.len() > 64 {
                return Err("lifecycle descendant ancestry cycles/exceeds bound".into());
            }
            let parent = (
                current
                    .parent_pid
                    .ok_or("lifecycle descendant parent absent")?,
                current
                    .parent_birth
                    .ok_or("lifecycle descendant parent birth absent")?,
            );
            if parent.1 > current.birth {
                return Err("lifecycle descendant parent birth postdates original child".into());
            }
            if original.get(&parent) == Some(&"target") {
                break;
            }
            current = descendants_by_identity
                .get(&parent)
                .ok_or("lifecycle descendant ancestry does not reach original target")?;
        }
    }
    // Transcript decoding belongs to the phase-specific root-first/held-tree
    // consumer; retaining it here must not stand in for native family custody.
    let transcript = raw["transcript"]
        .as_array()
        .ok_or("lifecycle original transcript rows absent")?;
    if transcript.len() > 1024
        || serde_json::to_vec(transcript)
            .map_err(|error| error.to_string())?
            .len()
            > 16 * 1024 * 1024
    {
        return Err("lifecycle original transcript exceeds bound".into());
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "Compare independent lifecycle identity, cell, worker, intent and native retirement evidence"
)]
pub(crate) fn validate_native_recovery(
    invocation: &Value,
    process: &Value,
    invocation_bytes: &[u8],
    stdout: &[u8],
    stderr: &[u8],
    owner: &Value,
    key: &CaseKey,
    selected_agent: &[u8],
    expected_cwd: &[u8],
) -> VerificationResult<()> {
    closed(
        invocation,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "lease_id",
            "key",
            "program",
            "arguments",
            "cwd_native_bytes",
            "timeout_millis",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
            "cleanup_deadline_scope",
            "cleared_environment",
            "selected_agent_sha256",
        ],
    )?;
    closed(
        process,
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
    closed(
        &process["native_image"],
        &["device", "inode", "length", "sha256"],
    )?;
    let cwd: Vec<u8> = serde_json::from_value(invocation["cwd_native_bytes"].clone())
        .map_err(|error| error.to_string())?;
    let before: HeldProcessIdentity =
        serde_json::from_value(process["preinput"].clone()).map_err(|error| error.to_string())?;
    let after: HeldProcessIdentity =
        serde_json::from_value(process["process"].clone()).map_err(|error| error.to_string())?;
    if invocation["format"] != "memcordon.linux-lifecycle-native-recovery-invocation"
        || invocation["revision"] != 1
        || invocation["identity"] != owner["identity"]
        || invocation["cell"] != owner["cell"]
        || invocation["lease_id"] != owner["lease_id"]
        || invocation["key"] != serde_json::to_value(key).map_err(|error| error.to_string())?
        || invocation["program"] != "/usr/libexec/memcordon-sealed-agent"
        || invocation["arguments"] != serde_json::json!(["package", "policy", "recover", "--json"])
        || cwd != expected_cwd
        || !cwd.starts_with(b"/")
        || cwd.contains(&0)
        || cwd.len() > 131072
        || invocation["timeout_millis"] != 60000
        || invocation["cleanup_deadline_scope"] != "original-installed-lease"
        || invocation["cleared_environment"] != true
        || invocation["work_deadline_unix_millis"] != owner["work_deadline_unix_millis"]
        || invocation["cleanup_deadline_unix_millis"] != owner["cleanup_deadline_unix_millis"]
        || invocation["selected_agent_sha256"] != sha256(selected_agent)
        || process["format"] != "memcordon.linux-lifecycle-native-recovery-process"
        || process["revision"] != 1
        || process["invocation_sha256"] != sha256(invocation_bytes)
        || process["stdout_sha256"] != sha256(stdout)
        || process["stderr_sha256"] != sha256(stderr)
        || process["raw_wait_status"] != 0
        || process["native_exit"] != 0
        || !process["signal"].is_null()
        || before.pid == 0
        || before.pid > i32::MAX as u32
        || before.birth == 0
        || before.retirement_observed
        || before.pid != after.pid
        || before.birth != after.birth
        || before.parent_pid != after.parent_pid
        || before.parent_birth != after.parent_birth
        || !after.retirement_observed
        || process["native_image"]["sha256"] != sha256(selected_agent)
        || process["native_image"]["length"] != selected_agent.len() as u64
        || ["device", "inode"].iter().any(|field| {
            process["native_image"][*field]
                .as_u64()
                .is_none_or(|value| value == 0)
        })
    {
        return Err(
            "lifecycle cleanup command substitutes original native image/process/deadline/capture"
                .into(),
        );
    }
    let recovered: Value = crate::wire::json(stdout)?;
    closed(&recovered, &["format", "revision", "outstanding"])?;
    if recovered["format"] != "memcordon.native-recovery"
        || recovered["revision"] != 1
        || recovered["outstanding"] != serde_json::json!([])
        || !stderr.is_empty()
    {
        return Err("lifecycle original native recovery retains outstanding obligations".into());
    }
    Ok(())
}

fn validate_owner(
    index: &EvidenceIndex,
    e: &LinuxLifecycleLossEvidence,
    product: &ProductObservation,
    owner: &Value,
    custody: &custody::Custody,
) -> VerificationResult<(Value, Value)> {
    validate_installed_owner(
        index,
        e,
        product,
        owner,
        custody,
        "lifecycle-owner.json",
        "memcordon.linux-lifecycle-owner",
    )
}
pub(crate) fn validate_installed_owner(
    index: &EvidenceIndex,
    e: &LinuxLifecycleLossEvidence,
    product: &ProductObservation,
    owner: &Value,
    custody: &custody::Custody,
    owner_leaf: &str,
    owner_format: &str,
) -> VerificationResult<(Value, Value)> {
    closed(
        owner,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "lease_id",
            "provider",
            "lease_owner",
            "acquisition",
            "activation",
            "contract",
            "runtime_manifest",
            "selected_cli",
            "selected_agent",
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
    let suffix = format!("/{owner_leaf}");
    let prefix = e
        .owner
        .strip_suffix(&suffix)
        .ok_or("installed native owner leaf differs")?;
    let decode = |field: &str, leaf: &str| -> VerificationResult<Value> {
        let path = owner[field]
            .as_str()
            .ok_or("lifecycle original peer path absent")?;
        if path != format!("{prefix}/{leaf}") {
            return Err("lifecycle original peer redirects custody scope".into());
        }
        crate::wire::json(custody.bytes(path)?)
    };
    let lease = decode("lease_owner", "original-lease-owner.json")?;
    let acquisition = decode("acquisition", "original-acquisition.json")?;
    let mut original_lease = None;
    for artifact in index
        .artifacts
        .iter()
        .filter(|artifact| artifact.path.rsplit('/').next() == Some("lease-owner.json"))
    {
        let original: Value = crate::wire::json(custody.bytes(&artifact.path)?)?;
        if original["identity"] == owner["identity"]
            && original["cell"] == owner["cell"]
            && original["lease_id"] == e.lease_id
            && original_lease.replace(original).is_some()
        {
            return Err("lifecycle original acquired lease is ambiguous".into());
        }
    }
    if original_lease.as_ref() != Some(&lease) {
        return Err("lifecycle copied lease differs from original pre-mutation acquisition".into());
    }
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
    closed(
        &acquisition,
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
    let expected_identity = serde_json::json!({"run_id":e.run_id,"source_commit":index.source_commit,"source_tree_sha256":index.source_tree_sha256,"version":product.version});
    let agent = product
        .components
        .iter()
        .find(|component| component.role == "sealed-agent")
        .ok_or("lifecycle installed agent absent")?;
    let cli = product
        .components
        .iter()
        .find(|component| component.role == "public-cli")
        .ok_or("lifecycle installed CLI absent")?;
    for (field, leaf, hash) in [
        (
            "selected_cli",
            "selected-cli-image.bin",
            cli.installed_sha256.as_str(),
        ),
        (
            "selected_agent",
            "selected-agent-image.bin",
            agent.installed_sha256.as_str(),
        ),
        (
            "runtime_manifest",
            "selected-runtime-manifest.json",
            custody.hash(&product.runtime_manifest)?,
        ),
    ] {
        let path = owner[field]
            .as_str()
            .ok_or("lifecycle selected original image path absent")?;
        if path != format!("{prefix}/{leaf}") || custody.hash(path)? != hash {
            return Err("lifecycle native selected product bytes differ".into());
        }
    }
    if owner["format"] != owner_format
        || owner["revision"] != 1
        || owner["identity"] != expected_identity
        || owner["cell"] != serde_json::to_value(&product.key).map_err(|error| error.to_string())?
        || owner["lease_id"] != e.lease_id
        || e.lease_id != product.lifecycle.lease_id
        || owner["provider"]["generation"] != format!("{}:{}", product.version, index.source_commit)
        || owner["provider"]["source_commit"] != index.source_commit
        || owner["provider"]["runtime_manifest_sha256"]
            != custody.hash(&product.runtime_manifest)?
        || lease["format"] != "memcordon.consumer-readiness.linux-lease-owner"
        || lease["revision"] != 1
        || acquisition["format"] != "memcordon.owned-readiness-resources"
        || acquisition["revision"] != 1
        || lease["cleanup_agent"] != "/usr/libexec/memcordon-sealed-agent"
        || lease["cleanup_agent_sha256"] != agent.installed_sha256
        || lease["legacy"] != acquisition["legacy"]
    {
        return Err("lifecycle original source/product/lease acquisition differs".into());
    }
    for original in [&lease, &acquisition] {
        if original["identity"] != owner["identity"] || original["cell"] != owner["cell"] {
            return Err("lifecycle resource acquisition crosses original source/cell".into());
        }
    }
    if lease["lease_id"] != owner["lease_id"]
        || lease["admin_root"] != acquisition["admin_root"]
        || lease["device"] != acquisition["device"]
        || lease["inode"] != acquisition["inode"]
        || lease["work_deadline_unix_millis"] != owner["work_deadline_unix_millis"]
        || lease["cleanup_deadline_unix_millis"] != owner["cleanup_deadline_unix_millis"]
        || lease["work_deadline_unix_millis"]
            .as_u64()
            .is_none_or(|value| value == 0)
        || lease["cleanup_deadline_unix_millis"].as_u64()
            <= lease["work_deadline_unix_millis"].as_u64()
    {
        return Err("lifecycle cleanup renews original resource authority/deadline".into());
    }
    let lifecycle: InstalledLifecycleJournal =
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
    if roots.len() != 1
        || lifecycle.run_id != e.run_id
        || lifecycle.lease_id != e.lease_id
        || lifecycle.source_commit != e.source_commit
        || lifecycle.source_tree_sha256 != e.source_tree_sha256
    {
        return Err("lifecycle original administrative custody journal absent".into());
    }
    let root: Value = crate::wire::json(custody.bytes(&roots[0].native_receipt)?)?;
    closed(&root, &["path", "device", "inode"])?;
    if root["path"] != lease["admin_root"]
        || root["device"] != lease["device"]
        || root["inode"] != lease["inode"]
    {
        return Err("lifecycle original held administrative inode substituted".into());
    }
    let artifact_root = lease["artifact_root"]
        .as_str()
        .ok_or("lifecycle original artifact root absent")?;
    if artifact_root.len() > 131072
        || !artifact_root.starts_with('/')
        || artifact_root.contains('\0')
        || artifact_root
            .split('/')
            .skip(1)
            .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(
            "lifecycle original acquired artifact scope is not absolute native custody".into(),
        );
    }
    Ok((acquisition, lease))
}

struct LifecycleContext {
    owner: Value,
    acquisition: Value,
    prepared: Value,
    native: Value,
    raw: Value,
    request: Value,
    input: FixtureInput,
    peers: BTreeMap<String, String>,
    case_directory: String,
    frontend_directory: String,
}

fn validate_worker(raw: &Value, prepared: &Value, agent_bytes: &[u8]) -> VerificationResult<Value> {
    closed(
        raw,
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
    closed(&raw["worker"], &["pid", "birth", "image_sha256"])?;
    closed(
        &raw["native_image"],
        &["device", "inode", "length", "sha256"],
    )?;
    let bytes: Vec<u8> =
        serde_json::from_value(raw["journal_bytes"].clone()).map_err(|error| error.to_string())?;
    let attempt = prepared["admission"]["attempt_id"]
        .as_str()
        .ok_or("lifecycle original worker attempt absent")?;
    let journal = crate::linux_recovery_route::decode_journal(&bytes, attempt)?;
    let worker = &raw["worker"];
    if raw["format"] != "memcordon.linux-prepared-worker-observation"
        || raw["revision"] != 1
        || raw["attempt_id"] != attempt
        || raw["provider"] != prepared["provider"]
        || raw["admission"] != prepared["admission"]
        || raw["journal_path"] != format!("/var/lib/memcordon/sealed/{attempt}")
        || raw["journal_sha256"] != sha256(&bytes)
        || ["journal_device", "journal_inode"]
            .iter()
            .any(|field| raw[*field].as_u64().is_none_or(|value| value == 0))
        || worker["pid"]
            .as_u64()
            .is_none_or(|value| value == 0 || value > i32::MAX as u64)
        || worker["birth"].as_u64().is_none_or(|value| value == 0)
        || worker["image_sha256"] != sha256(agent_bytes)
        || raw["native_image"]["sha256"] != sha256(agent_bytes)
        || raw["native_image"]["length"] != agent_bytes.len() as u64
        || ["device", "inode"].iter().any(|field| {
            raw["native_image"][*field]
                .as_u64()
                .is_none_or(|value| value == 0)
        })
        || journal["mixed_worker"]["pid"] != worker["pid"]
        || journal["mixed_worker"]["start_time"] != worker["birth"]
        || journal["mixed_admission_metadata"] != prepared["admission"]
    {
        return Err("lifecycle original worker protected journal/native image differs".into());
    }
    if journal["phase"] != "checkpoint-committed"
        || journal["release_knowledge"] != "not-released"
        || !journal["mixed_export_intent"].is_null()
    {
        return Err(
            "lifecycle pre-release worker imports later export/authorization authority".into(),
        );
    }
    for (field, role) in [
        ("frontend", "caller"),
        ("target", "target"),
        ("namespace_init", "namespace_init"),
        ("guardian", "guardian"),
    ] {
        if journal[field]["pid"] != prepared[role]["pid"]
            || journal[field]["start_time"] != prepared[role]["birth"]
        {
            return Err("lifecycle selected worker journal crosses original held family".into());
        }
    }
    Ok(worker.clone())
}

fn validate_frontend(
    context: &LifecycleContext,
    custody: &custody::Custody,
) -> VerificationResult<(Value, i32)> {
    let path = |role: &str| {
        context
            .peers
            .get(role)
            .map(String::as_str)
            .ok_or_else(|| format!("lifecycle original frontend peer absent: {role}"))
    };
    let decode = |role: &str| crate::wire::json(custody.bytes(path(role)?)?);
    let command = decode("frontend-invocation.json")?;
    let wait = decode("frontend-wait.json")?;
    let preinput = decode("frontend-preinput.json")?;
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
    closed(
        &preinput,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "lease_id",
            "key",
            "process",
            "held_at_prepared_barrier",
            "invocation_sha256",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
    )?;
    let before: HeldProcessIdentity =
        serde_json::from_value(preinput["process"].clone()).map_err(|error| error.to_string())?;
    let arguments: Vec<Vec<u8>> =
        serde_json::from_value(command["arguments"].clone()).map_err(|error| error.to_string())?;
    let program: Vec<u8> =
        serde_json::from_value(command["program"].clone()).map_err(|error| error.to_string())?;
    let target = match &context.input.target_argv {
        NativeArguments::UnixBytes(values) => values,
        _ => return Err("lifecycle original argv is not native Unix bytes".into()),
    };
    if arguments.len() != 21 + target.len()
        || program != b"/usr/bin/setpriv"
        || command["format"] != "memcordon.linux-owned-frontend-invocation"
        || command["revision"] != 1
        || command["environment_cleared"] != true
        || command["caller_uid"] != 65534
        || command["caller_gid"] != 65534
        || command["selected_cli_sha256"]
            != custody.hash(
                context.owner["selected_cli"]
                    .as_str()
                    .ok_or("lifecycle selected CLI path absent")?,
            )?
    {
        return Err("lifecycle actual frontend command/selected image differs".into());
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
        (8, "+300s"),
        (9, "--sealed"),
        (10, "--workload-contract"),
        (12, "--report-format"),
        (13, "result-v2"),
        (14, "--report"),
        (16, "--mixed-observation-directory"),
        (18, "--image-entrypoint"),
        (19, "owned-readiness"),
        (20, "--"),
    ] {
        if arguments[index] != text.as_bytes() {
            return Err("lifecycle native frontend invokes unrelated authority/budgets".into());
        }
    }
    if arguments[21..] != *target
        || arguments[11].is_empty()
        || arguments[15].is_empty()
        || [11, 15, 17]
            .iter()
            .any(|index| !arguments[*index].starts_with(b"/") || arguments[*index].contains(&0))
    {
        return Err("lifecycle original frontend paths/target arguments differ".into());
    }
    let report = std::str::from_utf8(&arguments[15]).map_err(|error| error.to_string())?;
    let directory = crate::linux_path::parent(report)
        .ok_or("lifecycle original frontend result parent absent")?;
    let original_case =
        crate::linux_path::parent(&directory).ok_or("lifecycle original case directory absent")?;
    if crate::linux_path::file_name(&directory) != Some("frontend")
        || crate::linux_path::file_name(report) != Some("result.json")
        || !crate::linux_path::equivalent(&original_case, &context.frontend_directory)
        || arguments[11]
            != crate::linux_path::join(&original_case, "mixed.contract.json").as_bytes()
        || arguments[17] != crate::linux_path::join(&directory, "observations").as_bytes()
    {
        return Err(
            "lifecycle frontend observation/contract scope crosses original result directory"
                .into(),
        );
    }
    if preinput["format"] != "memcordon.linux-lifecycle-frontend-preinput"
        || preinput["revision"] != 1
        || preinput["identity"] != context.owner["identity"]
        || preinput["cell"] != context.owner["cell"]
        || preinput["lease_id"] != context.owner["lease_id"]
        || preinput["key"]
            != serde_json::to_value(&context.input.key).map_err(|error| error.to_string())?
        || preinput["held_at_prepared_barrier"] != true
        || before.retirement_observed
        || before.pid == 0
        || before.pid > i32::MAX as u32
        || before.birth == 0
        || context.prepared["caller"]["pid"] != before.pid
        || context.prepared["caller"]["birth"] != before.birth
        || preinput["invocation_sha256"] != custody.hash(path("frontend-invocation.json")?)?
        || preinput["work_deadline_unix_millis"] != context.owner["work_deadline_unix_millis"]
        || preinput["cleanup_deadline_unix_millis"] != context.owner["cleanup_deadline_unix_millis"]
        || wait["format"] != "memcordon.linux-policy-frontend-exit"
        || wait["revision"] != 1
        || wait["process_id"] != before.pid
        || wait["process_birth"] != before.birth
        || wait["invocation_sha256"] != custody.hash(path("frontend-invocation.json")?)?
        || wait["stdout_sha256"] != custody.hash(path("stdout.bin")?)?
        || wait["stderr_sha256"] != custody.hash(path("stderr.bin")?)?
    {
        return Err("lifecycle actual frontend native wait/prepared custody differs".into());
    }
    let status = wait["raw_wait_status"]
        .as_i64()
        .and_then(|status| i32::try_from(status).ok())
        .ok_or("lifecycle actual raw wait absent")?;
    if let Some(code) = wait["native_exit"].as_i64() {
        if !(0..=255).contains(&code) || status != code as i32 * 256 || !wait["signal"].is_null() {
            return Err("lifecycle native exit is not original wait status".into());
        }
    } else {
        let signal = wait["signal"]
            .as_i64()
            .filter(|signal| (1..=64).contains(signal))
            .ok_or("lifecycle signalled wait lacks native signal")?;
        if status & 0x7f != signal as i32 || status & !0xff != 0 {
            return Err("lifecycle signal substitutes shell exit code".into());
        }
    }
    let mut public_arguments = vec![serde_json::json!({"display":"owned-readiness","raw":null})];
    for argument in target {
        public_arguments.push(serde_json::json!({"display":std::str::from_utf8(argument).map_err(|error|error.to_string())?,"raw":null}));
    }
    let public = serde_json::json!({"syntax":"plus-budgets-v1","budget_tokens":[{"kind":"memory","token":"+512M"},{"kind":"time","token":"+300s"}],"memory_token":"+512M","deadline_token":"+300s","argv":public_arguments});
    Ok((public, status))
}

fn validate_provider_request(
    context: &LifecycleContext,
    custody: &custody::Custody,
) -> VerificationResult<Value> {
    let path = context
        .peers
        .get("provider-request.bin")
        .ok_or("lifecycle original provider request bytes absent")?;
    let public: Value = crate::wire::json(custody.bytes(path)?)?;
    closed(
        &public,
        &[
            "format",
            "revision",
            "contract",
            "native_launch",
            "attempt_deadline_millis",
        ],
    )?;
    let request_digest = crate::wire::v3_request_digest(&context.request)?;
    let mut launch: Vec<u8> = serde_json::from_value(public["native_launch"].clone())
        .map_err(|error| error.to_string())?;
    launch.extend(hex::decode(&request_digest).map_err(|error| error.to_string())?);
    let arguments = match &context.input.target_argv {
        NativeArguments::UnixBytes(values) => values,
        _ => return Err("lifecycle native request argv encoding differs".into()),
    };
    if public["format"] != "memcordon.mixed-runtime-request"
        || public["revision"] != 2
        || public["contract"] != context.request
        || public["attempt_deadline_millis"] != 300000
        || context.prepared["admission"]["request_sha256"] != request_digest
        || context.prepared["admission"]["invocation_sha256"] != sha256(&launch)
    {
        return Err(
            "lifecycle actual provider request crosses original contract/budgets/admission".into(),
        );
    }
    crate::wire::validate_mixed_public_arguments_and_deadline(
        &launch,
        custody.bytes(
            context
                .peers
                .get("original-contract.json")
                .ok_or("lifecycle original contract bytes absent")?,
        )?,
        arguments,
        &[],
        Some(512 * 1024 * 1024),
        None,
    )?;
    Ok(public)
}

fn validate_boundary(
    context: &LifecycleContext,
    custody: &custody::Custody,
) -> VerificationResult<Value> {
    let observations = context.raw["observations"]
        .as_array()
        .filter(|rows| rows.len() <= 128)
        .ok_or("lifecycle original bounded observations absent")?;
    let key = serde_json::to_value(&context.input.key).map_err(|error| error.to_string())?;
    let allocation = observations
        .iter()
        .filter(|row| row["format"] == "memcordon.linux-lifecycle-allocation" && row["key"] == key)
        .collect::<Vec<_>>();
    if allocation.len() != 1 {
        return Err("lifecycle original before-ACK allocation is absent/ambiguous".into());
    }
    let allocation = allocation[0];
    closed(
        allocation,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "lease_id",
            "key",
            "attempt_id",
            "worker_index",
            "worker_source",
            "phase",
            "release_knowledge",
            "journal_sha256",
            "prepared",
            "frontend_invocation",
        ],
    )?;
    let path = |role: &str| {
        context
            .peers
            .get(role)
            .map(String::as_str)
            .ok_or_else(|| format!("lifecycle original boundary peer absent: {role}"))
    };
    let attempt = context.prepared["admission"]["attempt_id"]
        .as_str()
        .ok_or("lifecycle original admission attempt absent")?;
    let journal_bytes = custody.bytes(path("allocation-phase-journal.bin")?)?;
    let journal = crate::linux_recovery_route::decode_journal(journal_bytes, attempt)?;
    let command: Value = crate::wire::json(custody.bytes(path("frontend-invocation.json")?)?)?;
    if allocation["revision"] != 1
        || allocation["identity"] != context.owner["identity"]
        || allocation["cell"] != context.owner["cell"]
        || allocation["lease_id"] != context.owner["lease_id"]
        || allocation["attempt_id"] != attempt
        || allocation["worker_index"]
            .as_u64()
            .is_none_or(|index| index >= 128)
        || allocation["phase"] != "checkpoint-committed"
        || allocation["release_knowledge"] != "not-released"
        || journal["phase"] != allocation["phase"]
        || journal["release_knowledge"] != allocation["release_knowledge"]
        || allocation["journal_sha256"] != sha256(journal_bytes)
        || allocation["prepared"] != context.prepared
        || allocation["frontend_invocation"] != command
        || journal["mixed_admission_metadata"] != context.prepared["admission"]
    {
        return Err(
            "lifecycle allocation checkpoint substitutes original held request/phase".into(),
        );
    }
    let worker = validate_worker(
        &allocation["worker_source"],
        &context.prepared,
        custody.bytes(
            context.owner["selected_agent"]
                .as_str()
                .ok_or("lifecycle selected native agent bytes absent")?,
        )?,
    )?;
    if journal["mixed_worker"]["pid"] != worker["pid"]
        || journal["mixed_worker"]["start_time"] != worker["birth"]
    {
        return Err("lifecycle allocation associates a different original native worker".into());
    }
    if context.input.key.family == "L-LIFE-02" {
        let intervention = observations
            .iter()
            .filter(|row| {
                row["format"] == "memcordon.linux-lifecycle-intervention" && row["key"] == key
            })
            .collect::<Vec<_>>();
        if intervention.len() != 1 {
            return Err("lifecycle actual controller action observation absent/ambiguous".into());
        }
        closed(
            intervention[0],
            &["format", "revision", "key", "intent", "action"],
        )?;
        let intent: Value = crate::wire::json(custody.bytes(path("controller-intent.json")?)?)?;
        let action: Value = crate::wire::json(custody.bytes(path("controller-action.json")?)?)?;
        if intervention[0]["revision"] != 1
            || intervention[0]["intent"] != intent
            || intervention[0]["action"] != action
        {
            return Err(
                "lifecycle raw intervention observation differs from original native syscall"
                    .into(),
            );
        }
        if context.input.key.scenario.ends_with("-release") {
            let barrier: Value = crate::wire::json(custody.bytes(path("release-prepared.json")?)?)?;
            if intent["release_barrier"] != barrier {
                return Err(
                    "lifecycle final release barrier differs from original retained provider bytes"
                        .into(),
                );
            }
        } else if context.peers.contains_key("release-prepared.json") {
            return Err("lifecycle adopts release receipt outside selected final barrier".into());
        }
        validate_linux_lifecycle_intervention(
            &context.input.key,
            &intent,
            &action,
            &context.prepared,
            &worker,
            custody.bytes(path("phase-journal.bin")?)?,
            &context.owner["identity"],
            &context.owner["cell"],
            context.owner["lease_id"]
                .as_str()
                .ok_or("lifecycle original lease absent")?,
            custody.hash(
                context.owner["selected_cli"]
                    .as_str()
                    .ok_or("lifecycle selected CLI absent")?,
            )?,
            custody.hash(
                context.owner["selected_agent"]
                    .as_str()
                    .ok_or("lifecycle selected agent absent")?,
            )?,
        )?;
    }
    Ok(worker)
}

fn validate_carrier(
    context: &LifecycleContext,
    result: &Value,
    public: &Value,
    provider_request: &Value,
    index: &EvidenceIndex,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let wrapper = result["wrapper_status"]
        .as_i64()
        .and_then(|value| i32::try_from(value).ok())
        .filter(|value| (0..=255).contains(value))
        .ok_or("lifecycle actual published carrier status malformed")?;
    let caller = context.prepared["caller"]["pid"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or("lifecycle original carrier writer absent")?;
    crate::wire::validate_linux_public_result_envelope(
        result,
        public,
        &index.version,
        &context.input.key.target,
        wrapper,
        caller,
    )?;
    let request_bytes = custody.bytes(
        context
            .peers
            .get("provider-request.bin")
            .ok_or("lifecycle actual provider request absent")?,
    )?;
    let request_digest = crate::wire::v3_request_digest(&context.request)?;
    let attempt = context.prepared["admission"]["attempt_id"]
        .as_str()
        .ok_or("lifecycle original carrier attempt absent")?;
    let outcome = &result["runtime"]["outcome"];
    match outcome["kind"].as_str() {
        Some("indeterminate") => {
            closed(
                outcome,
                &[
                    "kind",
                    "attempt_id",
                    "request_sha256",
                    "retained_obligations",
                ],
            )?;
            let retained = &outcome["retained_obligations"];
            closed(retained, &["authorization", "obligations"])?;
            let obligations = retained["obligations"]
                .as_array()
                .filter(|rows| !rows.is_empty() && rows.len() <= 128)
                .ok_or("lifecycle original retained obligations absent/unbounded")?;
            let authorization = retained["authorization"]
                .as_str()
                .ok_or("lifecycle original authorization knowledge absent")?;
            if outcome["attempt_id"] != attempt
                || outcome["request_sha256"] != request_digest
                || wrapper != 125
                || !["authorized", "never-authorized", "unknown"].contains(&authorization)
                || (context.input.key.scenario.ends_with("-drain") && authorization != "authorized")
                || obligations.iter().any(|value| {
                    value
                        .as_str()
                        .is_none_or(|value| value.is_empty() || value.len() > 4096)
                })
            {
                return Err("lifecycle indeterminate carrier crosses original request/authorization knowledge".into());
            }
        }
        Some("rejected-before-authorization") => {
            closed(
                outcome,
                &[
                    "kind",
                    "request_sha256",
                    "request_bytes_sha256",
                    "reason",
                    "detail",
                    "allocation",
                ],
            )?;
            closed(&outcome["allocation"], &["authorization", "obligations"])?;
            if context.input.key.scenario.ends_with("-drain")
                || outcome["request_sha256"] != request_digest
                || outcome["request_bytes_sha256"] != sha256(request_bytes)
                || wrapper != 125
                || outcome["reason"] != "native-setup-failed"
                || outcome["detail"]
                    .as_str()
                    .is_none_or(|detail| detail.is_empty() || detail.len() > 4096)
                || outcome["allocation"]["authorization"] != "never-authorized"
                || outcome["allocation"]["obligations"] != serde_json::json!([])
            {
                return Err(
                    "lifecycle no-authorization carrier substitutes unrelated admission refusal"
                        .into(),
                );
            }
        }
        Some("executed") => validate_executed_carrier(context, outcome, provider_request, custody)?,
        _ => return Err("lifecycle original runtime outcome variant unsupported".into()),
    }
    Ok(())
}

fn validate_executed_carrier(
    context: &LifecycleContext,
    outcome: &Value,
    provider_request: &Value,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    if context.input.key.family == "L-LIFE-02" && !context.input.key.scenario.ends_with("-drain") {
        return Err(
            "lifecycle executed carrier contradicts unauthorizing original checkpoint".into(),
        );
    }
    closed(
        outcome,
        &[
            "kind",
            "admission",
            "request_bytes_sha256",
            "provider",
            "execution",
            "retirement",
        ],
    )?;
    let path = context
        .peers
        .get("provider-request.bin")
        .ok_or("lifecycle original executed request absent")?;
    if outcome["admission"] != context.prepared["admission"]
        || outcome["provider"] != context.owner["provider"]
        || outcome["request_bytes_sha256"] != custody.hash(path)?
        || provider_request["contract"] != context.request
    {
        return Err("lifecycle completed race substitutes original native transaction".into());
    }
    let execution = &outcome["execution"];
    let key = serde_json::to_value(&context.input.key).map_err(|error| error.to_string())?;
    let allocation = context.raw["observations"]
        .as_array()
        .ok_or("lifecycle original allocation absent")?
        .iter()
        .find(|row| row["format"] == "memcordon.linux-lifecycle-allocation" && row["key"] == key)
        .ok_or("lifecycle original native boot source absent")?;
    let journal_bytes: Vec<u8> =
        serde_json::from_value(allocation["worker_source"]["journal_bytes"].clone())
            .map_err(|error| error.to_string())?;
    let journal = crate::linux_recovery_route::decode_journal(
        &journal_bytes,
        context.prepared["admission"]["attempt_id"]
            .as_str()
            .ok_or("lifecycle original executed attempt absent")?,
    )?;
    closed(
        execution,
        &[
            "host_target",
            "boot_id",
            "caller",
            "target",
            "namespace_init",
            "guardian",
            "caller_uid",
            "caller_gid",
            "caller_user_namespace",
            "caller_mount_namespace",
            "caller_pid_namespace",
            "caller_network_namespace",
            "caller_ipc_namespace",
            "user_namespace",
            "mount_namespace",
            "pid_namespace",
            "network_namespace",
            "ipc_namespace",
            "root_device",
            "root_inode",
            "runtime_image",
            "input_image",
            "root_layout",
            "execution_identity",
            "target_uid",
            "target_gid",
            "supplementary_groups",
            "init_uid",
            "init_nondumpable",
            "no_new_privileges",
            "capabilities_empty",
            "filter_abi",
            "filter_instruction_sha256",
            "target_authorized",
            "exec_observed",
            "post_exec_descriptor_count",
            "native_wait_status",
            "outcome_origin",
            "authorization_monotonic_millis",
        ],
    )?;
    for (field, role) in [
        ("caller", "caller"),
        ("target", "target"),
        ("namespace_init", "namespace_init"),
        ("guardian", "guardian"),
    ] {
        if execution[field] != context.prepared[role] {
            return Err("lifecycle execution replaces original prepared native family".into());
        }
    }
    for (field, native_field) in [
        ("user_namespace", "user"),
        ("mount_namespace", "mount"),
        ("pid_namespace", "pid"),
        ("network_namespace", "network"),
        ("ipc_namespace", "ipc"),
    ] {
        if execution[field] != context.prepared[field]
            || execution[format!("caller_{field}")] != context.native["caller"][native_field]
        {
            return Err(
                "lifecycle executed carrier changes original independently observed namespaces"
                    .into(),
            );
        }
    }
    for field in [
        "runtime_image",
        "input_image",
        "root_layout",
        "execution_identity",
    ] {
        if execution[field] != context.request[field] {
            return Err(
                "lifecycle execution replaces original acquired image/root/account authority"
                    .into(),
            );
        }
    }
    if execution["host_target"] != context.input.key.target
        || execution["boot_id"] != journal["boot_identity"]
        || execution["caller_uid"] != 65534
        || execution["caller_gid"] != 65534
        || execution["init_uid"] != 0
        || execution["target_uid"] != context.acquisition["account"]["uid"]
        || execution["target_gid"] != context.acquisition["account"]["gid"]
        || execution["supplementary_groups"] != serde_json::json!([])
        || execution["post_exec_descriptor_count"] != 3
        || execution["root_device"] != context.prepared["root_device"]
        || execution["root_inode"] != context.prepared["root_inode"]
        || execution["authorization_monotonic_millis"]
            .as_u64()
            .is_none_or(|value| value == 0)
        || [
            "init_nondumpable",
            "no_new_privileges",
            "capabilities_empty",
            "target_authorized",
            "exec_observed",
        ]
        .iter()
        .any(|field| execution[*field] != true)
        || execution["filter_abi"]
            != if context.input.key.target.starts_with("x86_64-") {
                "x86_64"
            } else {
                "aarch64"
            }
    {
        return Err(
            "lifecycle completed native execution credential/root/filter facts differ".into(),
        );
    }
    digest(
        execution["filter_instruction_sha256"]
            .as_str()
            .ok_or("lifecycle actual filter commitment absent")?,
    )?;
    let mut filter_bytes = Vec::new();
    for instruction in crate::frozen_linux_filter_program(
        execution["filter_abi"]
            .as_str()
            .ok_or("lifecycle actual filter ABI absent")?,
    )? {
        filter_bytes.extend(instruction.code.to_le_bytes());
        filter_bytes.extend([instruction.jt, instruction.jf]);
        filter_bytes.extend(instruction.k.to_le_bytes());
    }
    if execution["filter_instruction_sha256"] != sha256(&filter_bytes) {
        return Err("lifecycle execution substitutes original frozen native filter".into());
    }
    let wait = execution["native_wait_status"]
        .as_i64()
        .and_then(|wait| i32::try_from(wait).ok())
        .ok_or("lifecycle original target native wait absent")?;
    match execution["outcome_origin"].as_str() {
        Some("native-exit") if wait & 0x7f == 0 => {}
        Some("native-signal") if (1..=64).contains(&(wait & 0x7f)) => {}
        _ => {
            return Err(
                "lifecycle completed race substitutes unrelated native outcome cause".into(),
            );
        }
    }
    let retirement = &outcome["retirement"];
    closed(
        retirement,
        &[
            "attempt_id",
            "workload_empty",
            "init_reaped",
            "guardian_reaped",
            "relays_drained_and_closed",
            "namespace_references_closed",
            "root_references_closed",
            "staging_removed",
            "account_quiescent",
            "reservation_retired",
            "export_receipt_sha256",
        ],
    )?;
    if retirement["attempt_id"] != context.prepared["admission"]["attempt_id"]
        || retirement["export_receipt_sha256"]
            != custody.hash(
                context
                    .peers
                    .get("export-receipt.json")
                    .ok_or("lifecycle original completed export receipt absent")?,
            )?
        || [
            "workload_empty",
            "init_reaped",
            "guardian_reaped",
            "relays_drained_and_closed",
            "namespace_references_closed",
            "root_references_closed",
            "staging_removed",
            "account_quiescent",
            "reservation_retired",
        ]
        .iter()
        .any(|field| retirement[*field] != true)
    {
        return Err(
            "lifecycle completed carrier lacks original retired export/account receipt".into(),
        );
    }
    let export: Value = crate::wire::json(
        custody.bytes(
            context
                .peers
                .get("export-receipt.json")
                .ok_or("lifecycle actual export receipt absent")?,
        )?,
    )?;
    closed(
        &export,
        &[
            "format",
            "revision",
            "attempt_id",
            "root_layout",
            "identity",
            "files",
        ],
    )?;
    if export["format"] != "memcordon.private-export"
        || export["revision"] != 1
        || export["attempt_id"] != retirement["attempt_id"]
        || export["root_layout"] != context.request["root_layout"]
        || export["identity"] != context.request["execution_identity"]["identity"]
    {
        return Err(
            "lifecycle completed export receipt crosses original layout/account/attempt".into(),
        );
    }
    let files = export["files"]
        .as_array()
        .ok_or("lifecycle original exported file census absent")?;
    if context.input.key.scenario.ends_with("-drain") {
        if files.len() != 2 || wait != 0 || execution["outcome_origin"] != "native-exit" {
            return Err("lifecycle completed root-first export/cause differs".into());
        }
        for (name, role) in [
            ("work/orphan-descendant.bin", "export-orphan-descendant.bin"),
            (
                "work/orphan-completion.json",
                "export-orphan-completion.json",
            ),
        ] {
            let rows = files
                .iter()
                .filter(|row| row["path"] == name)
                .collect::<Vec<_>>();
            if rows.len() != 1 {
                return Err(
                    "lifecycle completed original orphan export path absent/repeated".into(),
                );
            }
            closed(rows[0], &["path", "length", "sha256"])?;
            let bytes = custody.bytes(
                context
                    .peers
                    .get(role)
                    .ok_or("lifecycle original exported orphan bytes absent")?,
            )?;
            if rows[0]["length"] != bytes.len() as u64 || rows[0]["sha256"] != sha256(bytes) {
                return Err(
                    "lifecycle native exported orphan bytes differ from original receipt".into(),
                );
            }
            if role == "export-orphan-descendant.bin" {
                if bytes != (u8::MIN..=u8::MAX).collect::<Vec<_>>() {
                    return Err("lifecycle original orphan all-byte output differs".into());
                }
            } else {
                let completion: Value = crate::wire::json(bytes)?;
                closed(
                    &completion,
                    &[
                        "format",
                        "revision",
                        "challenge",
                        "pid",
                        "birth",
                        "original_parent_pid",
                        "original_parent_birth",
                        "reparented_pid",
                    ],
                )?;
                let family: Value = crate::wire::json(
                    custody.bytes(
                        context
                            .peers
                            .get("native-family-retirement.json")
                            .ok_or("lifecycle native orphan family absent")?,
                    )?,
                )?;
                let child = &family["descendants"][0];
                if completion["format"] != "memcordon.linux-orphan-completion"
                    || completion["revision"] != 1
                    || completion["challenge"]
                        != hex::encode(
                            custody.bytes(
                                context
                                    .peers
                                    .get("challenge.bin")
                                    .ok_or("lifecycle original orphan challenge absent")?,
                            )?,
                        )
                    || completion["pid"] != child["namespace_pid"]
                    || completion["birth"] != child["identity"]["birth"]
                    || context.native["target"]["namespace_pids"]
                        .as_array()
                        .and_then(|pids| pids.last())
                        != Some(&completion["original_parent_pid"])
                    || completion["original_parent_birth"] != context.prepared["target"]["birth"]
                    || completion["reparented_pid"] != 1
                {
                    return Err("lifecycle exported orphan completion substitutes original native namespace/birth/parent".into());
                }
            }
        }
    } else if !files.is_empty() {
        return Err("lifecycle bytes target adopts unrelated exported files".into());
    }
    Ok(())
}

fn validate_final_settlement(
    context: &LifecycleContext,
    worker: &Value,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let path = |role: &str| {
        context
            .peers
            .get(role)
            .map(String::as_str)
            .ok_or_else(|| format!("lifecycle original settlement peer absent: {role}"))
    };
    let decode = |role: &str| crate::wire::json(custody.bytes(path(role)?)?);
    let actor = if context.input.key.family == "L-LIFE-02" {
        decode("controller-intent.json")?
    } else {
        serde_json::json!({"actor":context.prepared["caller"]})
    };
    let family = decode("native-family-retirement.json")?;
    validate_linux_lifecycle_family_settlement(
        &family,
        &context.prepared,
        worker,
        &actor,
        &context.owner["identity"],
        &context.owner["cell"],
        context.owner["lease_id"]
            .as_str()
            .ok_or("lifecycle original settlement lease absent")?,
        &context.input.key,
    )?;
    let transcript = family["transcript"]
        .as_array()
        .ok_or("lifecycle original phase transcript absent")?;
    let descendants = family["descendants"]
        .as_array()
        .ok_or("lifecycle original phase descendants absent")?;
    if context.input.key.scenario.ends_with("-drain") {
        if transcript.len() != 1 || descendants.len() != 1 {
            return Err("lifecycle drain lacks original root-first held descendant".into());
        }
        let row = &transcript[0];
        closed(
            row,
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
        let stdout = custody.bytes(path("stdout.bin")?)?;
        let end = stdout
            .iter()
            .position(|byte| *byte == b'\n')
            .ok_or("lifecycle original root-first stdout row truncated")?;
        if crate::wire::json(&stdout[..end])? != *row {
            return Err(
                "lifecycle phase transcript differs from actual retained native output".into(),
            );
        }
        let child = &row["observation"];
        closed(child, &["pid", "birth", "parent_pid", "members"])?;
        let root_namespace = context.native["target"]["namespace_pids"]
            .as_array()
            .and_then(|pids| pids.last())
            .ok_or("lifecycle original native root namespace mapping absent")?;
        if row["format"] != "memcordon.linux-readiness-transcript"
            || row["revision"] != 1
            || row["sequence"] != 1
            || row["challenge"] != hex::encode(custody.bytes(path("challenge.bin")?)?)
            || row["operation"] != "root-exiting-before-held-descendant"
            || &row["root_pid"] != root_namespace
            || row["root_birth"] != context.prepared["target"]["birth"]
            || child["pid"] != descendants[0]["namespace_pid"]
            || child["birth"] != descendants[0]["identity"]["birth"]
            || &child["parent_pid"] != root_namespace
            || child["members"] != serde_json::json!([])
        {
            return Err(
                "lifecycle root-first transcript replaces physically held original descendant"
                    .into(),
            );
        }
    } else if !transcript.is_empty() || !descendants.is_empty() {
        return Err(
            "lifecycle preauthorization/delivery adopts unrelated executed descendant graph".into(),
        );
    }
    validate_native_recovery(
        &decode("native-recovery-invocation.json")?,
        &decode("native-recovery-process.json")?,
        custody.bytes(path("native-recovery-invocation.json")?)?,
        custody.bytes(path("native-recovery-stdout.bin")?)?,
        custody.bytes(path("native-recovery-stderr.bin")?)?,
        &context.owner,
        &context.input.key,
        custody.bytes(
            context.owner["selected_agent"]
                .as_str()
                .ok_or("lifecycle actual recovery agent bytes absent")?,
        )?,
        context.case_directory.as_bytes(),
    )?;
    let result_hash = if let Some(result) = context.peers.get("actual-result.json") {
        custody.hash(result)?.to_owned()
    } else {
        sha256(&[])
    };
    crate::validate_linux_refusal_census(
        &decode("recovered-ownership.json")?,
        &context.owner["identity"],
        &context.owner["cell"],
        context.owner["lease_id"]
            .as_str()
            .ok_or("lifecycle original census lease absent")?,
        &context.input.key.scenario,
        &context.acquisition["account"],
        &context.owner["provider"],
        custody.hash(path("provider-request.bin")?)?,
        &result_hash,
        context.prepared["admission"]["attempt_id"]
            .as_str()
            .ok_or("lifecycle original census attempt absent")?,
    )
}

fn validate_export_peer_applicability(
    context: &LifecycleContext,
    executed: bool,
) -> VerificationResult<()> {
    if context.peers.contains_key("export-receipt.json") != executed {
        return Err(
            "lifecycle export receipt presence substitutes original executed carrier".into(),
        );
    }
    let orphan = executed && context.input.key.scenario.ends_with("-drain");
    if [
        "export-orphan-descendant.bin",
        "export-orphan-completion.json",
    ]
    .iter()
    .any(|role| context.peers.contains_key(*role) != orphan)
    {
        return Err(
            "lifecycle orphan exports cross original executed root-first applicability".into(),
        );
    }
    Ok(())
}

pub(crate) fn verify_loss(
    index: &EvidenceIndex,
    record: &CaseRecord,
    e: &LinuxLifecycleLossEvidence,
    products: &BTreeMap<ProductKey, &ProductObservation>,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    if e.format != "memcordon.consumer-readiness.linux-lifecycle-loss" {
        return Err("lifecycle loss format differs".into());
    }
    let context = original_context(index, record, e, products, custody)?;
    let worker = validate_boundary(&context, custody)?;
    let (public, status) = validate_frontend(&context, custody)?;
    let provider_request = validate_provider_request(&context, custody)?;
    let present = context.raw["result_present"]
        .as_bool()
        .ok_or("lifecycle actual result presence malformed")?;
    if present {
        if !context.raw["result_absence_errno"].is_null() {
            return Err("lifecycle published result also claims native absence".into());
        }
        let path = context
            .peers
            .get("actual-result.json")
            .ok_or("lifecycle actual published result bytes absent")?;
        let result: Value = crate::wire::json(custody.bytes(path)?)?;
        validate_export_peer_applicability(
            &context,
            result["runtime"]["outcome"]["kind"] == "executed",
        )?;
        validate_carrier(
            &context,
            &result,
            &public,
            &provider_request,
            index,
            custody,
        )?;
        if status & 0x7f == 0 && result["wrapper_status"] != ((status >> 8) & 0xff) {
            return Err(
                "lifecycle original published result differs from native frontend exit".into(),
            );
        }
    } else if context.raw["result_absence_errno"] != 2
        || context.peers.contains_key("actual-result.json")
        || status == 0
    {
        return Err(
            "lifecycle loss substitutes fabricated result/absence or successful frontend".into(),
        );
    }
    if !present {
        validate_export_peer_applicability(&context, false)?;
    }
    if !present && !context.input.key.scenario.starts_with("frontend-") && status != 125 << 8 {
        return Err(
            "lifecycle missing-result infrastructure failure lacks native frontend exit 125".into(),
        );
    }
    if context.input.key.scenario.starts_with("frontend-") && status != 9 {
        return Err("lifecycle frontend kill did not produce actual native SIGKILL wait".into());
    }
    validate_final_settlement(&context, &worker, custody)
}

pub(crate) fn verify_delivery(
    index: &EvidenceIndex,
    record: &CaseRecord,
    e: &LinuxDeliveryEvidence,
    products: &BTreeMap<ProductKey, &ProductObservation>,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    if e.format != "memcordon.consumer-readiness.linux-delivery" {
        return Err("lifecycle delivery format differs".into());
    }
    let context = original_context(index, record, e, products, custody)?;
    let worker = validate_boundary(&context, custody)?;
    let (public, status) = validate_frontend(&context, custody)?;
    let provider_request = validate_provider_request(&context, custody)?;
    let path = |role: &str| {
        context
            .peers
            .get(role)
            .map(String::as_str)
            .ok_or_else(|| format!("lifecycle actual delivery peer absent: {role}"))
    };
    let decode = |role: &str| crate::wire::json(custody.bytes(path(role)?)?);
    if context.raw["result_present"] != false
        || !context.raw["result_absence_errno"].is_null()
        || context.raw["report_destination_directory"] != true
        || context.peers.contains_key("actual-result.json")
        || status != 125 * 256
    {
        return Err("lifecycle report persistence failure fabricates a result/ENOENT or substitutes native exit".into());
    }
    let before = decode("report-destination.json")?;
    let failure = decode("report-delivery-failure.json")?;
    closed(
        &before,
        &[
            "format",
            "revision",
            "path",
            "device",
            "inode",
            "uid",
            "gid",
            "mode",
            "is_directory",
        ],
    )?;
    closed(
        &failure,
        &[
            "format",
            "revision",
            "report_path",
            "submitted_report",
            "native_errno",
            "native_error_code",
            "destination",
            "frontend_pid",
        ],
    )?;
    closed(
        &failure["destination"],
        &["device", "inode", "uid", "gid", "mode", "is_directory"],
    )?;
    let command = decode("frontend-invocation.json")?;
    let arguments: Vec<Vec<u8>> =
        serde_json::from_value(command["arguments"].clone()).map_err(|error| error.to_string())?;
    if before["format"] != "memcordon.linux-report-destination"
        || before["revision"] != 1
        || failure["format"] != "memcordon.linux-native-report-delivery-failure"
        || failure["revision"] != 1
        || before["path"]
            != serde_json::to_value(&arguments[15]).map_err(|error| error.to_string())?
        || failure["report_path"] != before["path"]
        || failure["native_errno"] != 21
        || failure["native_error_code"] != "MCREPORT-WRITE"
        || failure["frontend_pid"] != context.prepared["caller"]["pid"]
        || before["is_directory"] != true
        || before["uid"] != 65534
        || before["gid"] != 65534
        || before["mode"]
            .as_u64()
            .is_none_or(|mode| mode & 0o170000 != 0o040000 || mode & 0o777 != 0o700)
        || ["device", "inode"]
            .iter()
            .any(|field| before[*field].as_u64().is_none_or(|value| value == 0))
    {
        return Err("lifecycle local persistence failure lacks original native EISDIR/directory/frontend association".into());
    }
    for field in ["device", "inode", "uid", "gid", "mode", "is_directory"] {
        if failure["destination"][field] != before[field] {
            return Err(
                "lifecycle report destination native identity changed across failed atomic write"
                    .into(),
            );
        }
    }
    let submitted: Vec<u8> = serde_json::from_value(failure["submitted_report"].clone())
        .map_err(|error| error.to_string())?;
    if submitted.is_empty() || submitted.len() > 16 * 1024 * 1024 {
        return Err("lifecycle original submitted report exceeds native bound".into());
    }
    let result: Value = crate::wire::json(&submitted)?;
    let terminal = decode("provider-terminal.json")?;
    if result["runtime"] != terminal
        || result["wrapper_status"] != 0
        || terminal["outcome"]["kind"] != "executed"
        || terminal["outcome"]["execution"]["native_wait_status"] != 0
        || terminal["outcome"]["execution"]["outcome_origin"] != "native-exit"
    {
        return Err("lifecycle persistence failure replaces original authenticated successful target terminal".into());
    }
    validate_carrier(
        &context,
        &result,
        &public,
        &provider_request,
        index,
        custody,
    )?;
    validate_export_peer_applicability(&context, true)?;
    // The genuine submitted status remains zero; only local report delivery
    // failed. The separate Child wait above remains the actual native 125.
    validate_final_settlement(&context, &worker, custody)
}

fn original_context(
    index: &EvidenceIndex,
    record: &CaseRecord,
    e: &LinuxLifecycleLossEvidence,
    products: &BTreeMap<ProductKey, &ProductObservation>,
    custody: &custody::Custody,
) -> VerificationResult<LifecycleContext> {
    let delivery = e.format == "memcordon.consumer-readiness.linux-delivery";
    header(
        &e.format,
        e.revision,
        if delivery {
            "memcordon.consumer-readiness.linux-delivery"
        } else {
            "memcordon.consumer-readiness.linux-lifecycle-loss"
        },
    )?;
    let origin = producer_origin(index, &record.key.target, record.key.channel.as_deref())?;
    if e.key != record.key
        || e.run_id != origin.run_id
        || e.source_commit != index.source_commit
        || e.source_tree_sha256 != index.source_tree_sha256
        || e.key.evidence_class != EvidenceClass::InstalledProduct
        || !e.key.target.ends_with("linux-gnu")
        || if delivery {
            e.key.family != "L-LIFE-05" || e.key.scenario != "report-persistence-failure"
        } else {
            e.key.family != "L-LIFE-02"
        }
    {
        return Err(
            "lifecycle raw evidence crosses original source/finite installed applicability".into(),
        );
    }
    if !delivery {
        let (actor, phase) = e
            .key
            .scenario
            .split_once('-')
            .ok_or("lifecycle finite selector absent")?;
        if !["frontend", "worker", "guardian", "control"].contains(&actor)
            || !["allocation", "release", "drain"].contains(&phase)
        {
            return Err("lifecycle selector outside original twelve".into());
        }
    }
    let product = products
        .get(&ProductKey {
            target: e.key.target.clone(),
            channel: e
                .key
                .channel
                .clone()
                .ok_or("lifecycle installed channel absent")?,
        })
        .copied()
        .ok_or("lifecycle original installed product absent")?;
    for path in e.artifact_paths() {
        custody.bytes(path)?;
    }
    let prefix = e
        .owner
        .strip_suffix("/lifecycle-owner.json")
        .ok_or("lifecycle original owner path differs")?;
    let mut peers = BTreeMap::new();
    let allowed = [
        "challenge.bin",
        "frontend-invocation.json",
        "frontend-preinput.json",
        "frontend-wait.json",
        "stdout.bin",
        "stderr.bin",
        "prepared.json",
        "prepared-native-before-ack.json",
        "allocation-phase-journal.bin",
        "phase-journal.bin",
        "controller-intent.json",
        "controller-action.json",
        "provider-request.bin",
        "native-family-retirement.json",
        "native-recovery-invocation.json",
        "native-recovery-process.json",
        "native-recovery-stdout.bin",
        "native-recovery-stderr.bin",
        "recovered-ownership.json",
        "original-lease-owner.json",
        "original-acquisition.json",
        "original-activation.json",
        "original-contract.json",
        "selected-runtime-manifest.json",
        "selected-cli-image.bin",
        "selected-agent-image.bin",
        "actual-result.json",
        "release-prepared.json",
        "export-receipt.json",
        "report-destination.json",
        "provider-terminal.json",
        "report-delivery-failure.json",
        "export-orphan-descendant.bin",
        "export-orphan-completion.json",
    ];
    for artifact in &e.artifacts {
        if !allowed.contains(&artifact.role.as_str())
            || artifact.path != format!("{prefix}/{}", artifact.role)
            || artifact.role.contains('/')
            || artifact.role.contains('\0')
            || peers
                .insert(artifact.role.clone(), artifact.path.clone())
                .is_some()
        {
            return Err("lifecycle raw peers repeat or redirect original custody".into());
        }
    }
    let forbidden = if delivery {
        vec![
            "phase-journal.bin",
            "controller-intent.json",
            "controller-action.json",
            "release-prepared.json",
            "actual-result.json",
        ]
    } else {
        vec![
            "report-destination.json",
            "provider-terminal.json",
            "report-delivery-failure.json",
        ]
    };
    if forbidden.iter().any(|role| peers.contains_key(*role)) {
        return Err(
            "lifecycle evidence adds authority from another finite delivery/loss scenario".into(),
        );
    }
    let path = |role: &str| -> VerificationResult<&str> {
        peers
            .get(role)
            .map(String::as_str)
            .ok_or_else(|| format!("lifecycle original raw peer absent: {role}"))
    };
    let decode = |role: &str| crate::wire::json(custody.bytes(path(role)?)?);
    for (actual, leaf) in [
        (&e.fixture, "fixture.bin"),
        (&e.fixture_source, "fixture-source.json"),
        (&e.input, "fixture-input.json"),
        (&e.raw, "lifecycle-loss-raw.json"),
    ] {
        if actual != &format!("{prefix}/{leaf}") {
            return Err("lifecycle original immutable source/input leaf differs".into());
        }
    }
    if custody.hash(&e.fixture)? != e.fixture_sha256
        || custody.hash(&e.fixture_source)? != e.fixture_source_sha256
        || custody.bytes(&e.fixture)?.is_empty()
    {
        return Err("lifecycle fixture/source bytes changed".into());
    }
    let fixture_source: Value = crate::wire::json(custody.bytes(&e.fixture_source)?)?;
    closed(&fixture_source, &["module", "entrypoint"])?;
    for field in ["module", "entrypoint"] {
        let bytes: Vec<u8> = serde_json::from_value(fixture_source[field].clone())
            .map_err(|error| error.to_string())?;
        if bytes.is_empty()
            || bytes.len() > 16 * 1024 * 1024
            || std::str::from_utf8(&bytes).is_err()
        {
            return Err("lifecycle retained original fixture source schema/bytes differ".into());
        }
    }
    let input: FixtureInput = crate::wire::decode(custody.bytes(&e.input)?)?;
    let challenge = custody.bytes(path("challenge.bin")?)?;
    let mut arguments = vec![
        if delivery {
            b"bytes-argv-status".to_vec()
        } else if e.key.scenario.ends_with("-drain") {
            b"root-first".to_vec()
        } else {
            b"held-tree".to_vec()
        },
        hex::encode(challenge).into_bytes(),
    ];
    if delivery {
        arguments.push(b"0".to_vec());
    }
    if challenge.len() != 32
        || challenge.iter().all(|byte| *byte == 0)
        || input.format != "memcordon.consumer-readiness.input"
        || input.revision != 1
        || input.run_id != e.run_id
        || input.key != e.key
        || input.challenge_sha256 != sha256(challenge)
        || !input.binary.is_empty()
        || !matches!(&input.target_argv,NativeArguments::UnixBytes(actual) if *actual==arguments)
        || input.deadline_millis != Some(300000)
        || input.memory_bytes != Some(512 * 1024 * 1024)
        || input.toolchain_identity.is_some()
    {
        return Err("lifecycle original fixture recipe/input budgets differ".into());
    }
    let owner: Value = crate::wire::json(custody.bytes(&e.owner)?)?;
    let (acquisition, lease) = validate_owner(index, e, product, &owner, custody)?;
    let case_directory = crate::linux_path::join(
        lease["artifact_root"]
            .as_str()
            .ok_or("lifecycle original artifact root absent")?,
        prefix,
    );
    let raw_parent = format!(
        "{}/{}/linux-mixed/recipe-",
        e.key.target,
        e.key.channel.as_deref().ok_or("lifecycle channel absent")?
    );
    let ordinal = prefix
        .strip_prefix(&raw_parent)
        .filter(|v| {
            !v.is_empty()
                && v.bytes().all(|b| b.is_ascii_digit())
                && (*v == "0" || !v.starts_with('0'))
        })
        .ok_or("lifecycle normalized recipe prefix differs from original driver")?;
    let original_leases = index
        .artifacts
        .iter()
        .filter(|artifact| artifact.path.ends_with("/lease-owner.json"))
        .filter_map(
            |artifact| match crate::wire::json(custody.bytes(&artifact.path).ok()?) {
                Ok(original) if original == lease => Some(artifact.path.as_str()),
                _ => None,
            },
        )
        .collect::<Vec<_>>();
    if original_leases.len() != 1 {
        return Err("lifecycle original acquired lease path ambiguous".into());
    }
    let native_lease = crate::linux_path::join(
        lease["artifact_root"]
            .as_str()
            .ok_or("lifecycle original artifact root absent")?,
        original_leases[0],
    );
    let frontend_directory = crate::linux_path::join(
        &crate::linux_path::parent(&native_lease)
            .ok_or("lifecycle original lease parent absent")?,
        &format!("mixed-cases/recipe-{ordinal}"),
    );
    let prepared = decode("prepared.json")?;
    let native = decode("prepared-native-before-ack.json")?;
    let request = decode("original-contract.json")?;
    let activation = decode("original-activation.json")?;
    crate::wire::validate_request(
        custody.bytes(path("original-contract.json")?)?,
        &e.key,
        OutcomeOrigin::Target,
    )?;
    let registry = crate::linux_policy::activation_registry(&activation)?;
    let fixture_length = custody.bytes(&e.fixture)?.len() as u64;
    if request["runtime_image"]
        != crate::linux_image_reference(&acquisition["images"]["runtime"], &e.key.target)?
        || request["input_image"]
            != crate::linux_image_reference(&acquisition["images"]["input"], &e.key.target)?
        || registry["legacy"] != acquisition["legacy"]
        || registry["execution_identities"]
            .as_array()
            .is_none_or(|rows| {
                rows.len() != 1
                    || rows[0]["uid"] != acquisition["account"]["uid"]
                    || rows[0]["gid"] != acquisition["account"]["gid"]
                    || rows[0]["enabled"] != true
            })
        || acquisition["images"]["runtime"]["entries"]
            .as_array()
            .is_none_or(|entries| {
                entries
                    .iter()
                    .filter(|entry| {
                        entry["path"] == "bin/owned-readiness"
                            && entry["kind"] == "regular"
                            && entry["sha256"] == e.fixture_sha256
                            && entry["size"] == fixture_length
                    })
                    .count()
                    != 1
            })
    {
        return Err(
            "lifecycle prepared selection substitutes original acquired image/account/fixture"
                .into(),
        );
    }
    let identity = registry["execution_identities"]
        .as_array()
        .and_then(|rows| rows.first())
        .ok_or("lifecycle actual selected identity absent")?;
    let layouts = registry["root_layouts"]
        .as_array()
        .filter(|rows| rows.len() == 1)
        .ok_or("lifecycle selected original root layout ambiguous")?;
    let grants = registry["grants"]
        .as_array()
        .filter(|rows| rows.len() == 1)
        .ok_or("lifecycle selected original grant ambiguous")?;
    let grant = &grants[0];
    let layout = &layouts[0];
    let selection = serde_json::json!({"identity":crate::linux_registry::linux_identity_reference(identity)?,"exclusive_use_policy":identity["exclusive_use_policy"]});
    let outputs = if e.key.scenario.ends_with("-drain") {
        serde_json::json!(["work/orphan-descendant.bin", "work/orphan-completion.json"])
    } else {
        serde_json::json!([])
    };
    if request["execution_identity"] != selection
        || request["root_layout"] != crate::linux_registry::linux_root_layout_reference(layout)?
        || layout["runtime_image"] != request["runtime_image"]
        || layout["input_image"] != request["input_image"]
        || identity["identity_id"] != "owned-readiness-identity"
        || identity["supplementary_groups"] != serde_json::json!([])
        || identity["reservation_key"] != "owned-readiness-reservation"
        || identity["exclusive_use_policy"]["id"] != "owned-exclusive-use"
        || identity["exclusive_use_policy"]
            != crate::linux_images::owned_exclusive_declaration_reference(
                &owner["identity"],
                &owner["cell"],
                &acquisition["account"],
            )?
        || layout["layout_id"] != "owned-readiness-root"
        || layout["output_files"] != outputs
        || layout["writable_roots"]
            != serde_json::json!([{"id":"work","path":"work","byte_limit":16u64*1024*1024*1024,"generated_execution":true}])
        || request["requirements"] != serde_json::json!([])
        || grant["id"] != "owned-readiness-grant"
        || grant["revision"] != 1
        || grant["id"] != request["authorization"]["grant_id"]
        || grant["revision"] != request["authorization"]["grant_revision"]
        || grant["enabled"] != true
        || grant["profile"] != request["authorized_profile"]
        || request["authorized_profile"]
            != crate::linux_registry::linux_combined_profile_reference()
        || grant["callers"] != serde_json::json!([{"platform":"linux","uid":65534}])
        || grant["approved_plans"] != serde_json::json!([request["workload_plan_digest"]])
        || request["authorization"]["approved_plan_digest"] != request["workload_plan_digest"]
    {
        return Err(
            "lifecycle actual contract/grant substitutes original finite image/account authority"
                .into(),
        );
    }
    if request["workload_plan_digest"] != crate::linux_images::owned_empty_plan_digest(&request)? {
        return Err(
            "lifecycle approved plan does not encode original acquired image/root/account tuple"
                .into(),
        );
    }
    for field in [
        "runtime_image",
        "input_image",
        "root_layout",
        "execution_identity",
    ] {
        if grant[field] != request[field] {
            return Err(
                "lifecycle actual selected grant differs from original requested authority".into(),
            );
        }
    }
    let attempt = prepared["admission"]["attempt_id"]
        .as_str()
        .ok_or("lifecycle original admitted attempt absent")?;
    crate::linux_policy::validate_prepared_native_graph(
        &prepared,
        &native,
        &request,
        &owner["provider"],
        &activation,
        custody.hash(path("prepared.json")?)?,
        &e.run_id,
        attempt,
    )?;
    let raw: Value = crate::wire::json(custody.bytes(&e.raw)?)?;
    closed(
        &raw,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "lease_id",
            "key",
            "observations",
            "frontend_wait",
            "result_present",
            "result_absence_errno",
            "report_destination_directory",
        ],
    )?;
    if raw["format"] != "memcordon.linux-lifecycle-loss-raw"
        || raw["revision"] != 1
        || raw["identity"] != owner["identity"]
        || raw["cell"] != owner["cell"]
        || raw["lease_id"] != e.lease_id
        || raw["key"] != serde_json::to_value(&e.key).map_err(|error| error.to_string())?
        || raw["report_destination_directory"] != delivery
        || raw["frontend_wait"] != decode("frontend-wait.json")?
    {
        return Err("lifecycle raw observation crosses original native owner/wait".into());
    }
    Ok(LifecycleContext {
        owner,
        acquisition,
        prepared,
        native,
        raw,
        request,
        input,
        peers,
        case_directory,
        frontend_directory,
    })
}
