use crate::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

const FORMAT: &str = "memcordon.consumer-readiness.linux-account-alias-policy-refusal";
const REJECTION: &[u8] =
    b"exclusive account id/uid/reservation alias across current or legacy policy\n";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct NativeAliasPolicyCommand {
    pub invocation: String,
    pub exit: String,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxAccountAliasPolicyEvidence {
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
    pub account_intent: String,
    pub account_readback: String,
    pub group_readback: String,
    pub candidate_policy: String,
    pub before: NativeAliasPolicyCommand,
    pub rejected: NativeAliasPolicyCommand,
    pub after: NativeAliasPolicyCommand,
}

impl LinuxAccountAliasPolicyEvidence {
    pub(crate) fn artifact_paths(&self) -> Vec<&str> {
        let mut paths = vec![
            self.owner.as_str(),
            &self.original_lease,
            &self.acquisition,
            &self.baseline_contract,
            &self.baseline_activation,
            &self.account_intent,
            &self.account_readback,
            &self.group_readback,
            &self.candidate_policy,
        ];
        for command in [&self.before, &self.rejected, &self.after] {
            paths.extend([
                command.invocation.as_str(),
                &command.exit,
                &command.stdout,
                &command.stderr,
            ]);
        }
        paths
    }
}

fn command(
    command: &NativeAliasPolicyCommand,
    custody: &custody::Custody,
    agent: &str,
    candidate: Option<&str>,
) -> VerificationResult<Value> {
    use crate::linux_account_refusal::closed;
    let invocation_bytes = custody.bytes(&command.invocation)?;
    let invocation = wire::json(invocation_bytes)?;
    let exit = wire::json(custody.bytes(&command.exit)?)?;
    let stdout = custody.bytes(&command.stdout)?;
    let stderr = custody.bytes(&command.stderr)?;
    let mut fields = vec![
        "format",
        "revision",
        "agent_sha256",
        "program",
        "arguments",
        "cwd",
        "environment_cleared",
        "budget_millis",
    ];
    if candidate.is_some() {
        fields.push("policy_sha256");
    }
    closed(&invocation, &fields)?;
    closed(
        &exit,
        &[
            "format",
            "revision",
            "native_exit",
            "success",
            "invocation_sha256",
            "stdout_sha256",
            "stderr_sha256",
        ],
    )?;
    let bytes = |value: &Value| -> VerificationResult<Vec<u8>> {
        serde_json::from_value(value.clone()).map_err(|error| error.to_string())
    };
    let arguments: Vec<Vec<u8>> = serde_json::from_value(invocation["arguments"].clone())
        .map_err(|error| error.to_string())?;
    let cwd_bytes = bytes(&invocation["cwd"])?;
    let cwd = std::str::from_utf8(&cwd_bytes).map_err(|error| error.to_string())?;
    if !crate::linux_path::is_normalized_absolute(cwd)
        || invocation["revision"] != 1
        || exit["revision"] != 1
        || invocation["agent_sha256"] != agent
        || bytes(&invocation["program"])? != b"/usr/libexec/memcordon-sealed-agent"
        || invocation["environment_cleared"] != true
        || invocation["budget_millis"]
            .as_u64()
            .is_none_or(|value| value == 0 || value > 60_000)
        || exit["invocation_sha256"] != sha256(invocation_bytes)
        || exit["stdout_sha256"] != sha256(stdout)
        || exit["stderr_sha256"] != sha256(stderr)
    {
        return Err("alias native command identity, budget or captures differ".into());
    }
    if let Some(candidate) = candidate {
        if invocation["format"] != "memcordon.linux-policy-activation-command"
            || exit["format"] != "memcordon.linux-policy-activation-exit"
            || arguments.len() != 5
            || arguments[..4]
                != [
                    b"package".to_vec(),
                    b"policy".to_vec(),
                    b"apply".to_vec(),
                    b"--file".to_vec(),
                ]
            || invocation["policy_sha256"] != custody.hash(candidate)?
            || exit["native_exit"] != 125
            || exit["success"] != false
            || !stdout.is_empty()
            || stderr != REJECTION
        {
            return Err(
                "alias policy must actually reject before activation with its exact native cause"
                    .into(),
            );
        }
    } else if invocation["format"] != "memcordon.linux-policy-inspection-command"
        || exit["format"] != "memcordon.linux-policy-inspection-exit"
        || arguments
            != [
                b"package".to_vec(),
                b"policy".to_vec(),
                b"inspect".to_vec(),
                b"--json".to_vec(),
            ]
        || exit["native_exit"] != 0
        || exit["success"] != true
        || !stderr.is_empty()
    {
        return Err("alias policy inspection lacks actual successful native capture".into());
    }
    Ok(invocation)
}

pub(crate) fn verify(
    index: &EvidenceIndex,
    record: &CaseRecord,
    e: &LinuxAccountAliasPolicyEvidence,
    products: &BTreeMap<ProductKey, &ProductObservation>,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    use crate::linux_account_refusal::{alias_plan_digest, closed};
    header(&e.format, e.revision, FORMAT)?;
    let origin = producer_origin(index, &record.key.target, record.key.channel.as_deref())?;
    if e.key != record.key
        || e.run_id != origin.run_id
        || e.source_commit != index.source_commit
        || e.source_tree_sha256 != index.source_tree_sha256
        || e.key.family != "L-ISO-06"
        || e.key.scenario != "account-alias"
        || e.key.evidence_class != EvidenceClass::InstalledProduct
        || !e.key.target.ends_with("linux-gnu")
    {
        return Err("alias policy refusal crosses original finite installed scope".into());
    }
    let product = products
        .get(&ProductKey {
            target: e.key.target.clone(),
            channel: e
                .key
                .channel
                .clone()
                .ok_or("alias installed channel absent")?,
        })
        .copied()
        .ok_or("alias installed product absent")?;
    if e.lease_id != product.lifecycle.lease_id {
        return Err("alias original installed lease differs".into());
    }
    for path in e.artifact_paths() {
        custody.bytes(path)?;
    }
    let decode = |path: &str| wire::json(custody.bytes(path)?);
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
        return Err("alias original acquisition/lease/source differs".into());
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
    let original = decode(&e.baseline_contract)?;
    let before = decode(&e.before.stdout)?;
    let after = decode(&e.after.stdout)?;
    if crate::linux_policy::activation_registry(&baseline)? != &owner["baseline_registry"]
        || baseline["registry_digest"]
            != crate::linux_registry::linux_registry_digest(
                &owner["baseline_registry"],
                &e.key.target,
            )?
        || baseline["epoch"] != owner["baseline_epoch"]
        || original["expected_epoch"] != baseline["epoch"]
        || crate::linux_policy::activation_registry(&before)? != &owner["baseline_registry"]
        || before != baseline
        || before != after
        || custody.bytes(&e.before.stdout)? != custody.bytes(&e.after.stdout)?
    {
        return Err("alias refused policy changed original authenticated activation".into());
    }
    let mut expected = owner["baseline_registry"].clone();
    expected["execution_identities"]
        .as_array()
        .filter(|rows| rows.len() == 1)
        .ok_or("alias requires sole original identity")?;
    expected["execution_identities"][0]["uid"] = 65534.into();
    expected["execution_identities"][0]["gid"] = 65534.into();
    let definition = &expected["execution_identities"][0];
    let reference = serde_json::json!({"identity":crate::linux_registry::linux_identity_reference(definition)?,"exclusive_use_policy":definition["exclusive_use_policy"]});
    let mut requested = original.clone();
    requested["execution_identity"] = reference.clone();
    let digest = alias_plan_digest(&requested)?;
    expected["grants"][0]["execution_identity"] = reference;
    expected["grants"][0]["approved_plans"] = serde_json::json!([digest]);
    if decode(&e.candidate_policy)? != expected
        || !expected["grants"][0]["callers"]
            .as_array()
            .is_some_and(|callers| {
                callers.contains(&serde_json::json!({"platform":"linux","uid":65534}))
            })
        || !expected["legacy"]["grants"]
            .as_array()
            .is_some_and(|grants| {
                grants.iter().any(|grant| {
                    grant["callers"].as_array().is_some_and(|callers| {
                        callers.contains(&serde_json::json!({"platform":"linux","uid":65534}))
                    })
                })
            })
    {
        return Err(
            "alias candidate changes unrelated authority or omits caller separation conflict"
                .into(),
        );
    }
    let agent = product
        .components
        .iter()
        .find(|component| component.role == "sealed-agent")
        .ok_or("alias installed agent absent")?;
    let before_command = command(&e.before, custody, &agent.installed_sha256, None)?;
    let rejected = command(
        &e.rejected,
        custody,
        &agent.installed_sha256,
        Some(&e.candidate_policy),
    )?;
    let after_command = command(&e.after, custody, &agent.installed_sha256, None)?;
    if before_command["cwd"] != rejected["cwd"] || after_command["cwd"] != rejected["cwd"] {
        return Err("alias native command group changes original case directory".into());
    }
    let cwd: Vec<u8> =
        serde_json::from_value(rejected["cwd"].clone()).map_err(|error| error.to_string())?;
    let cwd = std::str::from_utf8(&cwd).map_err(|error| error.to_string())?;
    let basename =
        crate::linux_path::file_name(cwd).ok_or("alias original case basename absent")?;
    let admin_root = owner["admin_root"]
        .as_str()
        .ok_or("alias original admin root absent")?;
    if !crate::linux_path::is_normalized_absolute(admin_root) {
        return Err("alias original admin root is not a canonical Linux absolute path".into());
    }
    let source = crate::linux_path::join(
        &crate::linux_path::join(admin_root, &format!("isolation-alias-{basename}")),
        "alias-rejection.policy.json",
    );
    let arguments: Vec<Vec<u8>> =
        serde_json::from_value(rejected["arguments"].clone()).map_err(|error| error.to_string())?;
    if arguments[4] != source.as_bytes() {
        return Err("alias policy candidate is not its original protected source".into());
    }
    Ok(())
}
