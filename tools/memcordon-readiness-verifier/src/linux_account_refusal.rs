use crate::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

/// Original no-target account admission, its native occupation, and its closure.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxAccountRefusalEvidence {
    pub format: String,
    pub revision: u32,
    pub key: CaseKey,
    pub run_id: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub lease_id: String,
    pub owner: String,
    pub original_lease: String,
    pub acquisition: String,
    pub baseline_contract: String,
    pub baseline_activation: String,
    pub contract: String,
    pub activation: String,
    pub challenge: String,
    pub public_invocation: String,
    pub frontend_invocation: String,
    pub frontend_exit: String,
    pub result: String,
    pub provider_request: String,
    pub stdout: String,
    pub stderr: String,
    pub census: String,
    pub account_intent: String,
    pub account_readback: String,
    pub group_readback: String,
    pub external_intent: Option<String>,
    pub external_image: Option<String>,
    pub external_live: Option<String>,
    pub external_at_refusal: Option<String>,
    pub external_retired: Option<String>,
    pub reservation_intent: Option<String>,
    pub reservation_live: Option<String>,
    pub reservation_retired: Option<String>,
    pub alias_policy: Option<String>,
    pub alias_invocation: Option<String>,
    pub alias_exit: Option<String>,
    pub alias_stderr: Option<String>,
    pub restoration: Option<String>,
    pub restoration_policy: Option<String>,
    pub restoration_invocation: Option<String>,
    pub restoration_exit: Option<String>,
    pub restoration_stderr: Option<String>,
}
impl LinuxAccountRefusalEvidence {
    pub(crate) fn artifact_paths(&self) -> Vec<&str> {
        let mut paths = vec![
            self.owner.as_str(),
            &self.original_lease,
            &self.acquisition,
            &self.baseline_contract,
            &self.baseline_activation,
            &self.contract,
            &self.activation,
            &self.challenge,
            &self.public_invocation,
            &self.frontend_invocation,
            &self.frontend_exit,
            &self.result,
            &self.provider_request,
            &self.stdout,
            &self.stderr,
            &self.census,
            &self.account_intent,
            &self.account_readback,
            &self.group_readback,
        ];
        for path in [
            &self.external_intent,
            &self.external_image,
            &self.external_live,
            &self.external_at_refusal,
            &self.external_retired,
            &self.reservation_intent,
            &self.reservation_live,
            &self.reservation_retired,
            &self.alias_policy,
            &self.alias_invocation,
            &self.alias_exit,
            &self.alias_stderr,
            &self.restoration,
            &self.restoration_policy,
            &self.restoration_invocation,
            &self.restoration_exit,
            &self.restoration_stderr,
        ]
        .into_iter()
        .flatten()
        {
            paths.push(path);
        }
        paths
    }
}

fn closed(value: &Value, fields: &[&str]) -> VerificationResult<()> {
    if value.as_object().is_none_or(|object| {
        object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field))
    }) {
        return Err("account refusal original raw schema differs".into());
    }
    Ok(())
}
fn bytes(value: &Value) -> VerificationResult<Vec<u8>> {
    serde_json::from_value(value.clone()).map_err(|error| error.to_string())
}

fn alias_plan_digest(contract: &Value) -> VerificationResult<String> {
    #[derive(Serialize)]
    struct Bound<'a> {
        id: &'a Value,
        digest: &'a Value,
    }
    #[derive(Serialize)]
    struct Identity<'a> {
        identity: Bound<'a>,
        exclusive_use_policy: Bound<'a>,
    }
    #[derive(Serialize)]
    struct Tcp<'a> {
        kind: &'static str,
        id: &'a Value,
        local_port: &'a Value,
        peer: &'a Value,
    }
    let bound = |value: &Value| -> VerificationResult<()> {
        closed(value, &["id", "digest"])?;
        Ok(())
    };
    for value in [
        &contract["runtime_image"],
        &contract["input_image"],
        &contract["root_layout"],
        &contract["execution_identity"]["identity"],
        &contract["execution_identity"]["exclusive_use_policy"],
    ] {
        bound(value)?;
    }
    let requirements = contract["requirements"]
        .as_array()
        .filter(|rows| rows.len() == 1)
        .ok_or("account alias original sole TCP requirement absent")?;
    let tcp = &requirements[0];
    closed(tcp, &["kind", "id", "local_port", "peer"])?;
    if tcp["kind"] != "tcp_listener"
        || tcp["local_port"] != serde_json::json!({"kind":"kernel_assigned"})
        || tcp["peer"] != serde_json::json!({"kind":"dynamic_loopback_within_this_attempt"})
    {
        return Err("account alias original TCP authority differs".into());
    }
    fn make(value: &Value) -> Bound<'_> {
        Bound {
            id: &value["id"],
            digest: &value["digest"],
        }
    }
    let identity = Identity {
        identity: make(&contract["execution_identity"]["identity"]),
        exclusive_use_policy: make(&contract["execution_identity"]["exclusive_use_policy"]),
    };
    let requirement = Tcp {
        kind: "tcp_listener",
        id: &tcp["id"],
        local_port: &tcp["local_port"],
        peer: &tcp["peer"],
    };
    Ok(sha256(
        &serde_json::to_vec(&(
            make(&contract["runtime_image"]),
            make(&contract["input_image"]),
            make(&contract["root_layout"]),
            identity,
            vec![requirement],
        ))
        .map_err(|error| error.to_string())?,
    ))
}

fn validate_external(
    e: &LinuxAccountRefusalEvidence,
    acquired: &Value,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let decode = |path: &str| crate::wire::json(custody.bytes(path)?);
    let intent_path = e
        .external_intent
        .as_deref()
        .ok_or("account original occupation command absent")?;
    let live_path = e
        .external_live
        .as_deref()
        .ok_or("account original occupation live receipt absent")?;
    let intent = decode(intent_path)?;
    let live = decode(live_path)?;
    let retired = decode(
        e.external_retired
            .as_deref()
            .ok_or("account occupation retirement absent")?,
    )?;
    closed(
        &intent,
        &[
            "format",
            "revision",
            "program",
            "arguments",
            "environment_cleared",
            "uid",
            "gid",
            "selected_executable_sha256",
        ],
    )?;
    closed(
        &live,
        &[
            "format",
            "revision",
            "intent_sha256",
            "held",
            "kernel_image",
            "native_status",
            "uid",
            "gid",
            "creator",
        ],
    )?;
    closed(&live["creator"], &["pid", "birth"])?;
    let uid = acquired["account"]["uid"]
        .as_u64()
        .ok_or("account original UID absent")?;
    let gid = acquired["account"]["gid"]
        .as_u64()
        .ok_or("account original GID absent")?;
    let args = vec![
        b"--reuid".to_vec(),
        uid.to_string().into_bytes(),
        b"--regid".to_vec(),
        gid.to_string().into_bytes(),
        b"--clear-groups".to_vec(),
        b"--".to_vec(),
        b"/usr/bin/sleep".to_vec(),
        b"300".to_vec(),
    ];
    let image = e
        .external_image
        .as_deref()
        .ok_or("account original occupation image absent")?;
    if intent["format"] != "memcordon.linux-external-account-task-intent"
        || intent["revision"] != 1
        || bytes(&intent["program"])? != b"/usr/bin/setpriv"
        || intent["arguments"] != serde_json::json!(args)
        || intent["environment_cleared"] != true
        || intent["uid"] != uid
        || intent["gid"] != gid
        || intent["selected_executable_sha256"] != custody.hash(image)?
        || custody.bytes(image)?.is_empty()
        || live["format"] != "memcordon.linux-external-account-task"
        || live["revision"] != 1
        || live["intent_sha256"] != custody.hash(intent_path)?
        || live["uid"] != uid
        || live["gid"] != gid
    {
        return Err("account occupation crosses actual original command/image/credentials".into());
    }
    let held = &live["held"];
    validate_snapshot(held)?;
    closed(
        &live["kernel_image"],
        &["device", "inode", "length", "sha256"],
    )?;
    if ["device", "inode"].iter().any(|field| {
        live["kernel_image"][*field]
            .as_u64()
            .is_none_or(|value| value == 0)
    }) || live["kernel_image"]["length"] != custody.bytes(image)?.len()
        || live["kernel_image"]["sha256"] != custody.hash(image)?
        || ["pid", "birth"].iter().any(|field| {
            live["creator"][*field]
                .as_u64()
                .is_none_or(|value| value == 0)
        })
        || live["creator"]["pid"] == held["process_id"]
        || live["creator"]["birth"].as_u64() > held["birth"].as_u64()
    {
        return Err("account occupation native creator/image identity differs".into());
    }
    let status = bytes(&live["native_status"])?;
    if status.len() > 131072 {
        return Err("account occupation raw credentials unbounded".into());
    }
    let text = std::str::from_utf8(&status).map_err(|error| error.to_string())?;
    for (prefix, expected) in [
        ("Uid:", vec![uid; 4]),
        ("Gid:", vec![gid; 4]),
        ("Groups:", vec![]),
    ] {
        let rows = text
            .lines()
            .filter_map(|line| line.strip_prefix(prefix))
            .collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err("account original credential tuple absent/duplicated".into());
        }
        let values = rows[0]
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        if values != expected {
            return Err(
                "account occupation does not hold actual exclusive native credentials".into(),
            );
        }
    }
    if let Some(path) = &e.external_at_refusal
        && decode(path)? != *held
    {
        return Err("account occupied original process differs at actual admission refusal".into());
    }
    closed(
        &retired,
        &[
            "format",
            "revision",
            "original_sha256",
            "held",
            "signal_sent",
            "raw_wait_status",
            "native_exit",
            "signal",
        ],
    )?;
    let identity: HeldProcessIdentity =
        serde_json::from_value(retired["held"].clone()).map_err(|error| error.to_string())?;
    if retired["format"] != "memcordon.linux-external-account-retired"
        || retired["revision"] != 1
        || retired["original_sha256"] != custody.hash(live_path)?
        || !identity.retirement_observed
        || held["process_id"] != identity.pid
        || held["birth"] != identity.birth
        || !(retired["signal_sent"] == true
            && retired["raw_wait_status"] == 9
            && retired["signal"] == 9
            && retired["native_exit"].is_null()
            || retired["signal_sent"] == false
                && retired["raw_wait_status"] == 0
                && retired["native_exit"] == 0
                && retired["signal"].is_null())
    {
        return Err("account occupation original Child/PIDFD retirement differs".into());
    }
    Ok(())
}

fn validate_snapshot(snapshot: &Value) -> VerificationResult<()> {
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
    if snapshot["process_id"]
        .as_u64()
        .is_none_or(|pid| pid == 0 || pid > i32::MAX as u64)
        || snapshot["birth"].as_u64().is_none_or(|birth| birth == 0)
        || snapshot["namespace_pids"].as_array().is_none_or(|pids| {
            pids.is_empty()
                || pids.first() != Some(&snapshot["process_id"])
                || pids.len() > 32
                || pids.iter().any(|pid| {
                    pid.as_u64()
                        .is_none_or(|pid| pid == 0 || pid > i32::MAX as u64)
                })
        })
    {
        return Err("account original native process snapshot differs".into());
    }
    for field in ["user", "mount", "pid", "network", "ipc"] {
        closed(&snapshot[field], &["device", "inode"])?;
        if ["device", "inode"].iter().any(|part| {
            snapshot[field][*part]
                .as_u64()
                .is_none_or(|value| value == 0)
        }) {
            return Err("account original native namespace identity absent".into());
        }
    }
    Ok(())
}

fn validate_reservation(
    e: &LinuxAccountRefusalEvidence,
    acquired: &Value,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let decode = |path: &str| crate::wire::json(custody.bytes(path)?);
    let intent = decode(
        e.reservation_intent
            .as_deref()
            .ok_or("account original stale intent absent")?,
    )?;
    let live = decode(
        e.reservation_live
            .as_deref()
            .ok_or("account original stale inode absent")?,
    )?;
    let retired = decode(
        e.reservation_retired
            .as_deref()
            .ok_or("account original stale closure absent")?,
    )?;
    let external = decode(
        e.external_live
            .as_deref()
            .ok_or("stale original retired process absent")?,
    )?;
    closed(
        &intent,
        &[
            "format",
            "revision",
            "path",
            "payload",
            "payload_sha256",
            "parent",
        ],
    )?;
    closed(
        &live,
        &[
            "format",
            "revision",
            "path",
            "payload",
            "device",
            "inode",
            "uid",
            "gid",
            "mode",
            "nlink",
            "payload_sha256",
            "parent",
            "parents",
        ],
    )?;
    closed(
        &retired,
        &[
            "format",
            "revision",
            "original",
            "path",
            "native_errno",
            "held_nlink",
            "closed",
            "parents",
        ],
    )?;
    let payload = &live["payload"];
    closed(
        payload,
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
    let uid = acquired["account"]["uid"]
        .as_u64()
        .ok_or("stale original account UID absent")?;
    let challenge = custody.bytes(&e.challenge)?;
    if challenge.len() != 32 {
        return Err("stale original challenge width differs".into());
    }
    let expected = format!(
        "/var/lib/memcordon/sealed/account-{}-{}-{uid}.reservation",
        payload["user_namespace_device"]
            .as_u64()
            .ok_or("stale original user namespace device absent")?,
        payload["user_namespace_inode"]
            .as_u64()
            .ok_or("stale original user namespace inode absent")?
    );
    if intent["format"] != "memcordon.linux-stale-reservation-intent"
        || intent["revision"] != 1
        || live["format"] != "memcordon.linux-stale-reservation-live"
        || live["revision"] != 1
        || payload["format"] != "memcordon.account-reservation"
        || payload["revision"] != 1
        || payload["uid"] != uid
        || bytes(&payload["attempt"])? != challenge[..16]
        || payload["owner_pid"] != external["held"]["process_id"]
        || payload["owner_birth"] != external["held"]["birth"]
        || payload["user_namespace_device"] != external["held"]["user"]["device"]
        || payload["user_namespace_inode"] != external["held"]["user"]["inode"]
        || payload["boot_identity"].as_str().is_none_or(|boot| {
            boot.len() != 36
                || boot
                    .bytes()
                    .any(|byte| !byte.is_ascii_hexdigit() && byte != b'-')
        })
        || live["path"] != expected
        || intent["path"] != expected
        || intent["payload"] != *payload
        || intent["parent"] != live["parent"]
        || live["payload_sha256"]
            != sha256(&serde_json::to_vec(payload).map_err(|error| error.to_string())?)
        || intent["payload_sha256"] != live["payload_sha256"]
        || live["uid"] != 0
        || live["nlink"] != 1
        || live["mode"]
            .as_u64()
            .is_none_or(|mode| mode & 0o170000 != 0o100000 || mode & 0o7777 != 0o600)
        || ["device", "inode"]
            .iter()
            .any(|field| live[*field].as_u64().is_none_or(|value| value == 0))
        || retired["format"] != "memcordon.linux-stale-reservation-retired"
        || retired["revision"] != 1
        || retired["original"] != live
        || retired["path"] != expected
        || retired["native_errno"] != 2
        || retired["held_nlink"] != 0
        || retired["closed"] != true
    {
        return Err("stale original reservation payload/inode/retired owner differs".into());
    }
    let parents = live["parents"]
        .as_array()
        .filter(|parents| parents.len() == 5)
        .ok_or("stale original protected ancestry incomplete")?;
    let closure = retired["parents"]
        .as_array()
        .filter(|parents| parents.len() == 5)
        .ok_or("stale original protected ancestry closure incomplete")?;
    for (ordinal, path) in [
        "/",
        "/var",
        "/var/lib",
        "/var/lib/memcordon",
        "/var/lib/memcordon/sealed",
    ]
    .into_iter()
    .enumerate()
    {
        let parent = &parents[ordinal];
        let retired = &closure[ordinal];
        closed(parent, &["path", "device", "inode", "uid", "mode", "nlink"])?;
        closed(
            retired,
            &[
                "index",
                "path",
                "device",
                "inode",
                "named_device",
                "named_inode",
                "uid",
                "mode",
                "closed",
                "native_errno",
            ],
        )?;
        if parent["path"] != path
            || parent["uid"] != 0
            || parent["mode"]
                .as_u64()
                .is_none_or(|mode| mode & 0o170000 != 0o040000 || mode & 0o022 != 0)
            || parent["nlink"].as_u64().is_none_or(|links| links == 0)
            || ["device", "inode"]
                .iter()
                .any(|field| parent[*field].as_u64().is_none_or(|value| value == 0))
            || retired["index"] != ordinal
            || retired["path"] != path
            || retired["device"] != parent["device"]
            || retired["inode"] != parent["inode"]
            || retired["named_device"] != parent["device"]
            || retired["named_inode"] != parent["inode"]
            || retired["uid"] != parent["uid"]
            || retired["mode"] != parent["mode"]
            || retired["closed"] != true
            || !retired["native_errno"].is_null()
        {
            return Err("stale original native protected ancestry/name/close differs".into());
        }
    }
    closed(&live["parent"], &["device", "inode", "uid", "mode"])?;
    for field in ["device", "inode", "uid", "mode"] {
        if live["parent"][field] != parents[4][field] {
            return Err("stale native owner parent differs from held ancestry".into());
        }
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "Compare independent occupied account, held process, policy and custody evidence"
)]
fn validate_scenario(
    e: &LinuxAccountRefusalEvidence,
    owner: &Value,
    original: &Value,
    contract: &Value,
    activation: &Value,
    acquired: &Value,
    agent: &str,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let decode = |path: &str| crate::wire::json(custody.bytes(path)?);
    let baseline = &owner["baseline_registry"];
    let active = crate::linux_policy::activation_registry(activation)?;
    let alias = e.key.scenario == "account-alias";
    let stale = e.key.scenario == "stale-reservation";
    let occupation = [
        &e.external_intent,
        &e.external_image,
        &e.external_live,
        &e.external_retired,
    ];
    let reservations = [
        &e.reservation_intent,
        &e.reservation_live,
        &e.reservation_retired,
    ];
    let mutations = [
        &e.alias_policy,
        &e.alias_invocation,
        &e.alias_exit,
        &e.alias_stderr,
        &e.restoration,
        &e.restoration_policy,
        &e.restoration_invocation,
        &e.restoration_exit,
        &e.restoration_stderr,
    ];
    if occupation.iter().any(|path| path.is_some() == alias)
        || reservations.iter().any(|path| path.is_some() != stale)
        || mutations.iter().any(|path| path.is_some() != alias)
        || e.external_at_refusal.is_some() != (e.key.scenario == "same-uid-process")
    {
        return Err("account original native scenario graph incomplete/cross-facet".into());
    }
    if alias {
        baseline["execution_identities"]
            .as_array()
            .filter(|rows| rows.len() == 1)
            .ok_or("account original sole identity absent")?;
        let mut expected = baseline.clone();
        expected["execution_identities"][0]["uid"] = 65534.into();
        expected["execution_identities"][0]["gid"] = 65534.into();
        let definition = &expected["execution_identities"][0];
        let reference = serde_json::json!({"identity":crate::linux_registry::linux_identity_reference(definition)?,"exclusive_use_policy":definition["exclusive_use_policy"]});
        let mut requested = original.clone();
        requested["execution_identity"] = reference.clone();
        requested["expected_epoch"] = activation["epoch"].clone();
        let digest = alias_plan_digest(&requested)?;
        requested["workload_plan_digest"] = digest.clone().into();
        requested["authorization"]["approved_plan_digest"] = digest.clone().into();
        crate::wire::v3_request_digest(&requested)?;
        expected["grants"][0]["execution_identity"] = reference;
        expected["grants"][0]["approved_plans"] = serde_json::json!([digest]);
        if active != &expected
            || *contract != requested
            || decode(e.alias_policy.as_deref().unwrap())? != expected
        {
            return Err("account alias changes unrelated original authority".into());
        }
        let restoration = decode(e.restoration.as_deref().unwrap())?;
        if crate::linux_policy::activation_registry(&restoration)? != baseline
            || decode(e.restoration_policy.as_deref().unwrap())? != *baseline
            || restoration["epoch"]["service_instance"] != activation["epoch"]["service_instance"]
            || restoration["epoch"]["revision"].as_u64() <= activation["epoch"]["revision"].as_u64()
        {
            return Err("account alias original native restoration differs".into());
        }
        for (invocation, exit, stderr, policy, receipt) in [
            (
                &e.alias_invocation,
                &e.alias_exit,
                &e.alias_stderr,
                &e.alias_policy,
                &e.activation,
            ),
            (
                &e.restoration_invocation,
                &e.restoration_exit,
                &e.restoration_stderr,
                &e.restoration_policy,
                e.restoration.as_ref().unwrap(),
            ),
        ] {
            let invocation = invocation.as_deref().unwrap();
            validate_linux_policy_command_capture(
                &decode(invocation)?,
                &decode(exit.as_deref().unwrap())?,
                custody.bytes(invocation)?,
                custody.bytes(receipt)?,
                custody.bytes(stderr.as_deref().unwrap())?,
                custody.bytes(policy.as_deref().unwrap())?,
                agent,
            )?;
        }
    } else {
        if active != baseline
            || *contract != *original
            || activation["epoch"] != owner["baseline_epoch"]
        {
            return Err("account busy probe replaces original acquired contract/authority".into());
        }
        validate_external(e, acquired, custody)?;
        if stale {
            validate_reservation(e, acquired, custody)?;
        }
    }
    Ok(())
}

pub(crate) fn verify(
    index: &EvidenceIndex,
    record: &CaseRecord,
    e: &LinuxAccountRefusalEvidence,
    products: &BTreeMap<ProductKey, &ProductObservation>,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    header(
        &e.format,
        e.revision,
        "memcordon.consumer-readiness.linux-account-refusal",
    )?;
    let origin = producer_origin(index, &record.key.target, record.key.channel.as_deref())?;
    if e.key != record.key
        || e.run_id != origin.run_id
        || e.source_commit != index.source_commit
        || e.source_tree_sha256 != index.source_tree_sha256
        || e.key.family != "L-ISO-06"
        || !["same-uid-process", "account-alias", "stale-reservation"]
            .contains(&e.key.scenario.as_str())
        || e.key.evidence_class != EvidenceClass::InstalledProduct
        || !e.key.target.ends_with("linux-gnu")
    {
        return Err("account refusal crosses finite original installed scope".into());
    }
    let product = products
        .get(&ProductKey {
            target: e.key.target.clone(),
            channel: e
                .key
                .channel
                .clone()
                .ok_or("account installed channel absent")?,
        })
        .copied()
        .ok_or("account selected original product absent")?;
    if e.lease_id != product.lifecycle.lease_id {
        return Err("account refusal crosses original installed lease".into());
    }
    for path in e.artifact_paths() {
        custody.bytes(path)?;
    }
    let decode = |path: &str| crate::wire::json(custody.bytes(path)?);
    let owner = decode(&e.owner)?;
    let lease = decode(&e.original_lease)?;
    let acquired = decode(&e.acquisition)?;
    closed(
        &owner,
        &[
            "format",
            "revision",
            "run_id",
            "source_commit",
            "source_tree_sha256",
            "cell",
            "lease_id",
            "provider",
            "baseline_registry",
            "baseline_epoch",
            "admin_root",
            "admin_root_device",
            "admin_root_inode",
            "privileged_policy_root",
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
    closed(
        &acquired,
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
    let identity = serde_json::json!({"run_id":e.run_id,"source_commit":index.source_commit,"source_tree_sha256":index.source_tree_sha256,"version":index.version});
    let cell = serde_json::to_value(&product.key).map_err(|error| error.to_string())?;
    if owner["format"] != "memcordon.linux-policy-case-owner"
        || owner["revision"] != 1
        || owner["run_id"] != e.run_id
        || owner["source_commit"] != e.source_commit
        || owner["source_tree_sha256"] != e.source_tree_sha256
        || owner["cell"] != cell
        || owner["lease_id"] != e.lease_id
        || lease["format"] != "memcordon.consumer-readiness.linux-lease-owner"
        || lease["revision"] != 1
        || lease["identity"] != identity
        || lease["cell"] != cell
        || lease["lease_id"] != e.lease_id
        || acquired["format"] != "memcordon.owned-readiness-resources"
        || acquired["revision"] != 1
        || acquired["identity"] != identity
        || acquired["cell"] != cell
        || lease["admin_root"] != owner["admin_root"]
        || acquired["admin_root"] != owner["admin_root"]
        || lease["device"] != owner["admin_root_device"]
        || lease["inode"] != owner["admin_root_inode"]
        || acquired["device"] != lease["device"]
        || acquired["inode"] != lease["inode"]
        || lease["legacy"] != acquired["legacy"]
    {
        return Err("account original acquisition/lease/source differs".into());
    }
    crate::linux_ingress::validate_owned_account(
        &acquired["account"],
        &decode(&e.account_intent)?,
        custody.bytes(&e.account_readback)?,
        custody.bytes(&e.group_readback)?,
        index,
        &e.key,
        &e.run_id,
        &e.acquisition,
        &owner,
        &lease,
    )?;
    let baseline = decode(&e.baseline_activation)?;
    let activation = decode(&e.activation)?;
    let contract = decode(&e.contract)?;
    let original = decode(&e.baseline_contract)?;
    if crate::linux_policy::activation_registry(&baseline)? != &owner["baseline_registry"]
        || baseline["epoch"] != owner["baseline_epoch"]
        || original["expected_epoch"] != baseline["epoch"]
        || contract["expected_epoch"] != activation["epoch"]
    {
        return Err("account original native policy/contract epoch differs".into());
    }
    let cli = product
        .components
        .iter()
        .find(|component| component.role == "public-cli")
        .ok_or("account selected original CLI absent")?;
    let public = decode(&e.public_invocation)?;
    let command = decode(&e.frontend_invocation)?;
    validate_linux_policy_frontend(
        &command,
        &public,
        custody.bytes(&e.challenge)?,
        65534,
        &cli.installed_sha256,
    )?;
    let arguments: Vec<Vec<u8>> =
        serde_json::from_value(command["arguments"].clone()).map_err(|error| error.to_string())?;
    crate::linux_ingress::validate_owned_frontend_launch(
        &decode(&e.provider_request)?,
        &arguments,
    )?;
    let exit = decode(&e.frontend_exit)?;
    closed(
        &exit,
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
    let pid = u32::try_from(
        exit["process_id"]
            .as_u64()
            .filter(|pid| *pid > 0)
            .ok_or("account original frontend PID absent")?,
    )
    .map_err(|error| error.to_string())?;
    if exit["format"] != "memcordon.linux-policy-frontend-exit"
        || exit["revision"] != 1
        || exit["process_birth"]
            .as_u64()
            .is_none_or(|birth| birth == 0)
        || exit["raw_wait_status"] != 125 * 256
        || exit["native_exit"] != 125
        || !exit["signal"].is_null()
        || exit["invocation_sha256"] != custody.hash(&e.frontend_invocation)?
        || exit["stdout_sha256"] != custody.hash(&e.stdout)?
        || exit["stderr_sha256"] != custody.hash(&e.stderr)?
    {
        return Err("account original Child wait/captures differ".into());
    }
    let result = decode(&e.result)?;
    let reason = if e.key.scenario == "account-alias" {
        "host-prerequisite-unavailable"
    } else {
        "exclusive-account-unavailable"
    };
    validate_linux_policy_refusal_result(
        &result,
        custody.bytes(&e.provider_request)?,
        &contract,
        &public,
        &product.version,
        &e.key.target,
        125,
        pid,
        reason,
    )?;
    if e.key.scenario == "account-alias"
        && result["runtime"]["outcome"]["detail"]
            != "exclusive target must be enabled and distinct from frontend"
    {
        return Err("account alias original native rejection cause differs".into());
    }
    let attempt = e
        .provider_request
        .rsplit('/')
        .next()
        .and_then(|name| name.strip_suffix(".provider-request.bin"))
        .ok_or("account original provider request basename absent")?;
    let census = decode(&e.census)?;
    validate_linux_refusal_census(
        &census,
        &identity,
        &cell,
        &e.lease_id,
        &e.key.scenario,
        &acquired["account"],
        &owner["provider"],
        custody.hash(&e.provider_request)?,
        custody.hash(&e.result)?,
        attempt,
    )?;
    let agent = product
        .components
        .iter()
        .find(|component| component.role == "sealed-agent")
        .ok_or("account selected original agent absent")?;
    validate_scenario(
        e,
        &owner,
        &original,
        &contract,
        &activation,
        &acquired,
        &agent.installed_sha256,
        custody,
    )
}
