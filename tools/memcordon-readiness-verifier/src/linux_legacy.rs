//! Frozen installed codecs: public requests and original native command custody.
use crate::*;
use serde_json::Value;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxFrozenLegacyCommand {
    pub action: String,
    pub invocation: String,
    pub creation: String,
    pub exit: String,
    pub stdout: String,
    pub stderr: String,
    pub result: Option<String>,
    pub provider_request: Option<String>,
    pub provider_terminal: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxFrozenLegacyEvidence {
    pub format: String,
    pub revision: u32,
    pub key: CaseKey,
    pub run_id: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub lease_id: String,
    pub owner: String,
    pub original_lease: String,
    pub request: String,
    pub cli: String,
    pub fixture: String,
    pub launcher: String,
    pub activation: BTreeMap<String, String>,
    pub commands: Vec<LinuxFrozenLegacyCommand>,
}
impl LinuxFrozenLegacyEvidence {
    pub(crate) fn artifact_paths(&self) -> Vec<&str> {
        let mut paths = vec![
            self.owner.as_str(),
            &self.original_lease,
            &self.request,
            &self.cli,
            &self.fixture,
            &self.launcher,
        ];
        paths.extend(self.activation.values().map(String::as_str));
        for c in &self.commands {
            paths.extend([
                c.invocation.as_str(),
                &c.creation,
                &c.exit,
                &c.stdout,
                &c.stderr,
            ]);
            for path in [&c.result, &c.provider_request, &c.provider_terminal]
                .into_iter()
                .flatten()
            {
                paths.push(path);
            }
        }
        paths
    }
}
fn closed(v: &Value, names: &[&str]) -> VerificationResult<()> {
    let map = v.as_object().ok_or("frozen member is not an object")?;
    if map.len() != names.len() || names.iter().any(|name| !map.contains_key(*name)) {
        return Err("frozen member unknown/missing fields".into());
    }
    Ok(())
}
fn bytes(v: &Value) -> VerificationResult<Vec<u8>> {
    serde_json::from_value(v.clone()).map_err(|e| e.to_string())
}
fn text(out: &mut Vec<u8>, v: &Value) -> VerificationResult<()> {
    let s = v
        .as_str()
        .filter(|s| !s.is_empty() && s.len() <= 65535 && !s.contains('\0'))
        .ok_or("frozen canonical text absent")?;
    out.extend((s.len() as u16).to_be_bytes());
    out.extend(s.as_bytes());
    Ok(())
}
fn digest_bytes(out: &mut Vec<u8>, v: &Value) -> VerificationResult<()> {
    let s = v.as_str().ok_or("frozen digest absent")?;
    digest(s)?;
    out.extend(hex::decode(s).map_err(|e| e.to_string())?);
    Ok(())
}
fn domain(s: &str) -> Vec<u8> {
    let mut out = s.as_bytes().to_vec();
    out.extend([0, 0, 1]);
    out
}
fn private_ceiling() -> Value {
    serde_json::json!({"direct_socket_authority":"attempt-private-ipv4-stack-all-ports","unix_authority":"no-named-endpoints-socket-pairs-only","external_socket_custody":"no-socket-at-target-entry","credential_gains":"no-gain","mediated_communication":"external-filesystem-and-stdio-policy-accepted"})
}
fn baseline_ceiling() -> Value {
    serde_json::json!({"direct_socket_authority":"pinned-legacy-socket-filter-accepted","unix_authority":"existing-host-unix-authority-accepted","external_socket_custody":"existing-stdio-authority-accepted","credential_gains":"existing-caller-envelope-accepted","mediated_communication":"external-filesystem-and-stdio-policy-accepted"})
}
fn baseline_profile() -> VerificationResult<Value> {
    let mut out = domain("profile-definition-v1");
    text(&mut out, &serde_json::json!("linux-unix-create-v1"))?;
    out.extend([1, 2, 2, 2, 1, 1, 1]);
    Ok(serde_json::json!({"id":"linux-unix-create-v1","semantic_digest":sha256(&out)}))
}
fn profile() -> VerificationResult<Value> {
    let mut out = domain("profile-definition-v2");
    text(&mut out, &serde_json::json!("linux-tcp4-private-v1"))?;
    out.extend([3, 1, 1, 1, 1, 1, 1, 1, 1]);
    for n in [0u64, 32768, 60999] {
        out.extend(n.to_be_bytes());
    }
    out.extend(0u16.to_be_bytes());
    Ok(serde_json::json!({"id":"linux-tcp4-private-v1","semantic_digest":sha256(&out)}))
}
/// Empty requirements/endpoints are the actual five installed compatibility commands.
/// V1 and V2 retain separate domains; no production canonical encoder is used.
pub fn linux_frozen_request_digest(request: &Value) -> VerificationResult<String> {
    let version = request["schema_version"]
        .as_u64()
        .filter(|v| *v == 1 || *v == 2)
        .ok_or("frozen request version differs")?;
    let mut fields = vec![
        "schema_version",
        "workload_plan_digest",
        "authorized_profile",
        "authorization",
        "ceiling",
        "requirements",
        "endpoints",
        "expected_epoch",
    ];
    if version == 2 {
        fields.push("execution_identity");
    }
    closed(request, &fields)?;
    if request["ceiling"]
        != if version == 1 {
            baseline_ceiling()
        } else {
            private_ceiling()
        }
        || request["authorized_profile"]
            != if version == 1 {
                baseline_profile()?
            } else {
                profile()?
            }
        || request["requirements"] != serde_json::json!([])
        || request["endpoints"] != serde_json::json!([])
    {
        return Err("frozen scope/family/profile requirements differ".into());
    }
    closed(
        &request["authorization"],
        &["grant_id", "grant_revision", "approved_plan_digest"],
    )?;
    closed(
        &request["expected_epoch"],
        &["service_instance", "revision"],
    )?;
    if request["authorization"]["grant_id"] != "installed-preserved"
        || request["authorization"]["grant_revision"] != 1
        || request["authorization"]["approved_plan_digest"] != request["workload_plan_digest"]
    {
        return Err("frozen original grant/plan association differs".into());
    }
    let mut out = domain(if version == 1 {
        "memcordon-workload-contract-v1"
    } else {
        "memcordon-workload-contract-v2"
    });
    digest_bytes(&mut out, &request["workload_plan_digest"])?;
    text(&mut out, &request["authorized_profile"]["id"])?;
    digest_bytes(&mut out, &request["authorized_profile"]["semantic_digest"])?;
    text(&mut out, &request["authorization"]["grant_id"])?;
    out.extend(1u64.to_be_bytes());
    digest_bytes(&mut out, &request["workload_plan_digest"])?;
    out.extend(if version == 1 {
        [1, 2, 2, 2, 1]
    } else {
        [3, 1, 1, 1, 1]
    });
    out.extend([0, 0, 0, 0]);
    let nonce: Vec<u8> = bytes(&request["expected_epoch"]["service_instance"])?;
    if nonce.len() != 16 || nonce.iter().all(|v| *v == 0) {
        return Err("frozen native epoch nonce differs".into());
    }
    out.extend(nonce);
    out.extend(
        request["expected_epoch"]["revision"]
            .as_u64()
            .filter(|n| *n > 0)
            .ok_or("frozen epoch revision absent")?
            .to_be_bytes(),
    );
    if version == 2 {
        if request["execution_identity"] != serde_json::json!({"kind":"preserve-caller"}) {
            return Err("frozen V2 caller identity changed".into());
        }
        out.push(1);
    }
    Ok(sha256(&out))
}
fn validate_registry(
    registry: &Value,
    request: &Value,
    fixture_hash: &str,
) -> VerificationResult<()> {
    if request["schema_version"] == 1 {
        closed(
            registry,
            &[
                "format",
                "revision",
                "profiles",
                "grants",
                "active_attempt_disposition",
            ],
        )?;
        if registry["format"] != "memcordon.local-policy"
            || registry["revision"] != 1
            || registry["active_attempt_disposition"] != "drain-existing"
            || registry["profiles"]
                != serde_json::json!([{"profile":"linux-unix-create","reference":baseline_profile()?,"enabled":true}])
            || registry["grants"]
                != serde_json::json!([{"id":"installed-preserved","revision":1,"profile":baseline_profile()?,"ceiling":baseline_ceiling(),"enabled":true,"callers":[{"platform":"linux","uid":65534}],"approved_plans":[fixture_hash]}])
            || request["workload_plan_digest"] != fixture_hash
        {
            return Err("frozen V1 actual qualified grant catalogue differs".into());
        }
        return Ok(());
    }
    crate::linux_registry::legacy_digest(registry)?;
    let profiles = registry["profiles"]
        .as_array()
        .ok_or("frozen profiles absent")?;
    if profiles.len() != 1
        || profiles[0]
            != serde_json::json!({"profile":"linux-tcp4-private-v1","reference":profile()?,"enabled":true})
    {
        return Err("frozen actual profile catalogue differs".into());
    }
    let identities = registry["execution_identities"]
        .as_array()
        .ok_or("frozen original identities absent")?;
    if identities.len() != 1 {
        return Err("frozen original identity catalogue differs".into());
    }
    let identity = &identities[0];
    if identity["enabled"] != true
        || identity["uid"] != 65533
        || identity["gid"] != 65533
        || identity["supplementary_groups"] != serde_json::json!([])
        || identity["reference"]["id"] != "installed-delegated"
    {
        return Err("frozen administrator identity native account differs".into());
    }
    let entries = identity["entrypoints"]
        .as_array()
        .ok_or("frozen entrypoints absent")?;
    if entries.len() != 1
        || entries[0]["id"] != "installed-fixture"
        || entries[0]["absolute_path"] != "/usr/libexec/memcordon-installed-private-fixture"
        || entries[0]["sha256"] != fixture_hash
    {
        return Err("frozen approved native executable differs".into());
    }
    let mut encoded = domain("execution-identity-v2");
    text(&mut encoded, &identity["reference"]["id"])?;
    encoded.extend(65533u64.to_be_bytes());
    encoded.extend(65533u64.to_be_bytes());
    encoded.extend(0u16.to_be_bytes());
    encoded.extend(1u16.to_be_bytes());
    text(&mut encoded, &entries[0]["id"])?;
    text(&mut encoded, &entries[0]["absolute_path"])?;
    encoded.extend(
        entries[0]["size"]
            .as_u64()
            .filter(|v| *v > 0)
            .ok_or("frozen original executable size absent")?
            .to_be_bytes(),
    );
    digest_bytes(&mut encoded, &entries[0]["sha256"])?;
    if identity["reference"]["semantic_digest"] != sha256(&encoded) {
        return Err("frozen V2 original identity canonical reference differs".into());
    }
    let grants = registry["grants"]
        .as_array()
        .ok_or("frozen original grants absent")?;
    if grants.len() != 2 {
        return Err("frozen original grant catalogue differs".into());
    }
    for (name, execution) in [
        (
            "installed-preserved",
            serde_json::json!({"kind":"preserve-caller"}),
        ),
        (
            "installed-delegated",
            serde_json::json!({"kind":"administrator-profile","reference":identity["reference"]}),
        ),
    ] {
        let rows = grants
            .iter()
            .filter(|g| g["id"] == name)
            .collect::<Vec<_>>();
        if rows.len() != 1 {
            return Err("frozen grant missing/duplicated".into());
        }
        let g = rows[0];
        if g["revision"] != 1
            || g["profile"] != request["authorized_profile"]
            || g["ceiling"] != private_ceiling()
            || g["enabled"] != true
            || g["callers"] != serde_json::json!([{"platform":"linux","uid":65534}])
            || g["approved_plans"] != serde_json::json!([fixture_hash])
            || g["execution_identity"] != execution
        {
            return Err("frozen grant native caller/identity/plan differs".into());
        }
    }
    if request["workload_plan_digest"] != fixture_hash {
        return Err("frozen approved plan is not measured installed fixture".into());
    }
    Ok(())
}
fn baseline_registry_digest(registry: &Value) -> VerificationResult<String> {
    let profile = baseline_profile()?;
    let grant = &registry["grants"][0];
    let mut out = domain("memcordon.local-policy/revision1");
    out.extend(1u16.to_be_bytes());
    text(&mut out, &profile["id"])?;
    digest_bytes(&mut out, &profile["semantic_digest"])?;
    out.push(1);
    out.extend(1u16.to_be_bytes());
    text(&mut out, &grant["id"])?;
    out.extend(1u64.to_be_bytes());
    text(&mut out, &profile["id"])?;
    digest_bytes(&mut out, &profile["semantic_digest"])?;
    out.extend([1, 2, 2, 2, 1, 1]);
    out.extend(1u16.to_be_bytes());
    out.push(1);
    out.extend(65534u32.to_be_bytes());
    out.extend(1u16.to_be_bytes());
    digest_bytes(&mut out, &grant["approved_plans"][0])?;
    out.push(1);
    Ok(sha256(&out))
}
fn validate_activation(
    e: &LinuxFrozenLegacyEvidence,
    owner: &Value,
    product: &ProductObservation,
    custody: &custody::Custody,
    prefix: &str,
    version: u64,
) -> VerificationResult<()> {
    let stem = if version == 1 {
        "v1-activation"
    } else {
        "v2-restoration"
    };
    let leaves = [
        "policy.json",
        "invocation.json",
        "creation.json",
        "stdout.json",
        "stderr.bin",
        "exit.json",
    ];
    if e.activation.len() != leaves.len() {
        return Err("frozen activation graph incomplete".into());
    }
    for leaf in leaves {
        if e.activation.get(leaf) != Some(&format!("{prefix}/{stem}.{leaf}")) {
            return Err("frozen activation crosses original command scope".into());
        }
    }
    let get = |leaf: &str| -> VerificationResult<Value> {
        wire::json(
            custody.bytes(
                e.activation
                    .get(leaf)
                    .ok_or("frozen activation peer absent")?,
            )?,
        )
    };
    let policy = get("policy.json")?;
    let activation = get("stdout.json")?;
    let invocation = get("invocation.json")?;
    let creation = get("creation.json")?;
    let exit = get("exit.json")?;
    closed(
        &activation,
        &[
            "format",
            "revision",
            "registry",
            "registry_digest",
            "epoch",
            "revoked_admissions",
        ],
    )?;
    if activation["format"]
        != if version == 1 {
            "memcordon.local-activation"
        } else {
            "memcordon.local-private-activation"
        }
        || activation["revision"] != 1
        || activation["revoked_admissions"] != serde_json::json!([])
    {
        return Err("frozen original drain activation format differs".into());
    }
    if policy != owner["registry"]
        || activation["registry"] != policy
        || activation["epoch"] != owner["contract"]["expected_epoch"]
    {
        return Err("frozen actual activation/readback epoch differs".into());
    }
    let expected_digest = if version == 1 {
        baseline_registry_digest(&policy)?
    } else {
        crate::linux_registry::legacy_digest(&policy)?
    };
    if activation["registry_digest"] != expected_digest {
        return Err("frozen activation canonical original registry digest differs".into());
    }
    closed(
        &invocation,
        &[
            "program",
            "arguments",
            "cwd",
            "environment",
            "started_unix_millis",
            "work_deadline_unix_millis",
            "budget_millis",
            "selected_image",
        ],
    )?;
    closed(&creation, &["identity", "kernel_image", "stat"])?;
    closed(
        &exit,
        &[
            "identity",
            "native_status",
            "invocation_sha256",
            "stdout_sha256",
            "stderr_sha256",
        ],
    )?;
    let before: HeldProcessIdentity =
        serde_json::from_value(creation["identity"].clone()).map_err(|e| e.to_string())?;
    let after: HeldProcessIdentity =
        serde_json::from_value(exit["identity"].clone()).map_err(|e| e.to_string())?;
    let raw_stat = String::from_utf8(bytes(&creation["stat"])?).map_err(|e| e.to_string())?;
    if raw_stat
        .split_whitespace()
        .next()
        .and_then(|s| s.parse::<u32>().ok())
        != Some(before.pid)
        || raw_stat
            .rsplit_once(") ")
            .and_then(|(_, s)| s.split_whitespace().nth(19))
            .and_then(|s| s.parse::<u64>().ok())
            != Some(before.birth)
    {
        return Err("frozen policy native creation birth differs".into());
    }
    let agent = product
        .components
        .iter()
        .find(|c| c.role == "sealed-agent")
        .ok_or("frozen installed agent absent")?;
    let image = &invocation["selected_image"];
    closed(
        image,
        &["path", "device", "inode", "length", "sha256", "uid", "mode"],
    )?;
    closed(
        &creation["kernel_image"],
        &["device", "inode", "length", "sha256"],
    )?;
    let start = invocation["started_unix_millis"]
        .as_u64()
        .ok_or("frozen activation start absent")?;
    let cutoff = owner["work_deadline_unix_millis"]
        .as_u64()
        .ok_or("frozen original cutoff absent")?;
    let budget = invocation["budget_millis"]
        .as_u64()
        .ok_or("frozen activation budget absent")?;
    let native_policy = format!(
        "{}/frozen-legacy/{stem}.policy.json",
        owner["output"]
            .as_str()
            .ok_or("frozen original output absent")?
    );
    if invocation["program"] != serde_json::json!(b"/usr/libexec/memcordon-sealed-agent".as_slice())
        || invocation["arguments"]
            != serde_json::json!([
                b"package".as_slice(),
                b"policy",
                b"apply",
                b"--registry",
                native_policy.as_bytes()
            ])
        || invocation["cwd"]
            != serde_json::json!(
                owner["work"]
                    .as_str()
                    .ok_or("frozen original cwd absent")?
                    .as_bytes()
            )
        || invocation["environment"] != serde_json::json!([])
        || invocation["work_deadline_unix_millis"] != cutoff
        || start == 0
        || start >= cutoff
        || budget == 0
        || budget > 60000
        || budget > cutoff - start
        || image["sha256"] != agent.installed_sha256
        || image["uid"] != 0
        || image["mode"].as_u64().is_none_or(|m| m & 0o022 != 0)
        || ["device", "inode", "length", "sha256"]
            .iter()
            .any(|f| image[*f] != creation["kernel_image"][*f])
        || before.pid == 0
        || before.pid > i32::MAX as u32
        || before.birth == 0
        || before.retirement_observed
        || !after.retirement_observed
        || before.pid != after.pid
        || before.birth != after.birth
        || exit["native_status"] != 0
        || exit["invocation_sha256"] != custody.hash(&e.activation["invocation.json"])?
        || exit["stdout_sha256"] != custody.hash(&e.activation["stdout.json"])?
        || exit["stderr_sha256"] != custody.hash(&e.activation["stderr.bin"])?
        || !custody.bytes(&e.activation["stderr.bin"])?.is_empty()
    {
        return Err("frozen measured native activation custody/cutoff differs".into());
    }
    Ok(())
}
fn validate_baseline_plan(
    plan: &Value,
    request: &Value,
    registry: &Value,
) -> VerificationResult<()> {
    closed(
        plan,
        &[
            "format",
            "revision",
            "request",
            "registry_digest",
            "provider",
            "boot_identity",
            "effective_policy_digest",
        ],
    )?;
    let request_digest = linux_frozen_request_digest(request)?;
    let registry_digest = baseline_registry_digest(registry)?;
    if plan["format"] != "memcordon.local-plan"
        || plan["revision"] != 1
        || plan["registry_digest"] != registry_digest
        || plan["request"]
            != serde_json::json!({"request_digest":request_digest,"workload_plan_digest":request["workload_plan_digest"],"profile":request["authorized_profile"],"authorization":request["authorization"],"epoch":request["expected_epoch"]})
        || plan["boot_identity"].as_str().is_none_or(|s| s.is_empty())
    {
        return Err("frozen V1 original plan/request/epoch binding differs".into());
    }
    let mut effective = domain("effective-workload-policy-v1");
    digest_bytes(&mut effective, &plan["request"]["request_digest"])?;
    digest_bytes(
        &mut effective,
        &request["authorized_profile"]["semantic_digest"],
    )?;
    digest_bytes(&mut effective, &plan["registry_digest"])?;
    effective.extend([1, 2, 2, 2, 1]);
    if plan["effective_policy_digest"] != sha256(&effective) {
        return Err("frozen V1 effective policy canonical digest differs".into());
    }
    Ok(())
}
fn validate_baseline_result(
    public: &Value,
    request: &Value,
    owner: &Value,
    stdout: &[u8],
    group: u64,
) -> VerificationResult<()> {
    if !public["private_execution"].is_null() {
        return Err("frozen V1 entered V2 private runtime".into());
    }
    let workload = &public["policy"]["effective"]["workload"];
    closed(
        workload,
        &["state", "binding", "effective", "preauthorization"],
    )?;
    if workload["state"] != "admitted"
        || workload["effective"]
            != serde_json::json!({"profile":"linux-unix-create","ceiling":baseline_ceiling(),"restriction":"linux-unix-only-socket-syscall-filter-alternate-paths-unknown"})
    {
        return Err("frozen V1 effective qualified baseline differs".into());
    }
    let admission = &workload["binding"];
    closed(
        admission,
        &[
            "format",
            "revision",
            "plan",
            "attempt_id",
            "restart_attempt",
            "admission_nonce",
            "caller_invocation_reference",
        ],
    )?;
    validate_baseline_plan(&admission["plan"], request, &owner["registry"])?;
    if admission["format"] != "memcordon.local-attempt-binding"
        || admission["revision"] != 1
        || admission["restart_attempt"] != 0
        || admission["attempt_id"]
            .as_str()
            .is_none_or(|s| s.is_empty())
    {
        return Err("frozen V1 original attempt absent".into());
    }
    for field in ["admission_nonce", "caller_invocation_reference"] {
        let value = bytes(&admission[field])?;
        if value.len() != 16 || value.iter().all(|b| *b == 0) {
            return Err("frozen V1 native association nonce invalid".into());
        }
    }
    let plan = &admission["plan"];
    let binding = &plan["request"];
    let mut encoded = domain("memcordon.local-attempt-binding/revision1");
    digest_bytes(&mut encoded, &binding["request_digest"])?;
    digest_bytes(&mut encoded, &binding["workload_plan_digest"])?;
    text(&mut encoded, &binding["profile"]["id"])?;
    digest_bytes(&mut encoded, &binding["profile"]["semantic_digest"])?;
    text(&mut encoded, &binding["authorization"]["grant_id"])?;
    encoded.extend(1u64.to_be_bytes());
    digest_bytes(
        &mut encoded,
        &binding["authorization"]["approved_plan_digest"],
    )?;
    encoded.extend(bytes(&binding["epoch"]["service_instance"])?);
    encoded.extend(
        binding["epoch"]["revision"]
            .as_u64()
            .ok_or("frozen native epoch revision absent")?
            .to_be_bytes(),
    );
    digest_bytes(&mut encoded, &plan["registry_digest"])?;
    text(&mut encoded, &plan["provider"]["generation"])?;
    text(&mut encoded, &plan["provider"]["source_commit"])?;
    digest_bytes(&mut encoded, &plan["provider"]["runtime_manifest_sha256"])?;
    text(&mut encoded, &plan["boot_identity"])?;
    digest_bytes(&mut encoded, &plan["effective_policy_digest"])?;
    text(&mut encoded, &admission["attempt_id"])?;
    encoded.extend(0u64.to_be_bytes());
    encoded.extend(bytes(&admission["admission_nonce"])?);
    encoded.extend(bytes(&admission["caller_invocation_reference"])?);
    let attempt_digest = sha256(&encoded);
    let attempts = public["attempts"]
        .as_array()
        .filter(|a| a.len() == 1)
        .ok_or("frozen V1 original attempt cardinality differs")?;
    let enforcement = &attempts[0]["policy_enforcement"];
    closed(
        enforcement,
        &["state", "admission", "before_authorization", "terminal"],
    )?;
    if enforcement["state"] != "authorized" || enforcement["admission"] != *admission {
        return Err("frozen V1 original admission differs from result attempt".into());
    }
    let checkpoint = &enforcement["before_authorization"];
    closed(
        checkpoint,
        &[
            "attempt_binding",
            "digest",
            "controls",
            "target_gated",
            "caller_verified",
            "resources_verified",
            "guardian_verified",
            "epoch_verified",
            "durable",
        ],
    )?;
    if checkpoint["controls"] != "linux-unix-only-socket-syscall-filter-alternate-paths-unknown"
        || [
            "target_gated",
            "caller_verified",
            "resources_verified",
            "guardian_verified",
            "epoch_verified",
            "durable",
        ]
        .iter()
        .any(|f| checkpoint[*f] != true)
        || workload["preauthorization"] != checkpoint["digest"]
    {
        return Err("frozen V1 actual preauthorization controls differ".into());
    }
    let mut checkpoint_bytes = domain("attempt-policy-enforcement-v1");
    digest_bytes(&mut checkpoint_bytes, &serde_json::json!(attempt_digest))?;
    checkpoint_bytes.extend([1, 1, 1, 1, 1, 1, 1]);
    if checkpoint["attempt_binding"] != attempt_digest
        || checkpoint["digest"] != sha256(&checkpoint_bytes)
    {
        return Err("frozen V1 independent native checkpoint digest differs".into());
    }
    let terminal = &enforcement["terminal"];
    closed(
        terminal,
        &[
            "state",
            "attempt_binding",
            "checkpoint",
            "controls_preserved",
            "provider_resources_closed",
        ],
    )?;
    if terminal["state"] != "retired"
        || terminal["attempt_binding"] != checkpoint["attempt_binding"]
        || terminal["checkpoint"] != checkpoint["digest"]
        || terminal["controls_preserved"] != true
        || terminal["provider_resources_closed"] != true
    {
        return Err("frozen V1 original terminal controls/retirement differ".into());
    }
    let fixture = wire::json(stdout)?;
    closed(
        &fixture,
        &[
            "format",
            "revision",
            "pid",
            "birth",
            "uid",
            "gid",
            "groups",
            "unix_bytes",
            "denials",
        ],
    )?;
    if fixture["format"] != "memcordon.frozen-linux-unix-baseline"
        || fixture["revision"] != 1
        || fixture["pid"] != public["launch"]["target_pid"]
        || fixture["pid"]
            .as_u64()
            .is_none_or(|p| p == 0 || p > i32::MAX as u64)
        || fixture["birth"].as_u64().is_none_or(|b| b == 0)
        || fixture["uid"] != serde_json::json!([65534, 65534, 65534, 65534])
        || fixture["gid"] != serde_json::json!([65534, 65534, 65534, 65534])
        || fixture["groups"] != serde_json::json!([group])
        || fixture["unix_bytes"] != serde_json::json!(b"frozen-unix-baseline".as_slice())
        || fixture["denials"]
            != serde_json::json!([{"family":2,"native_errno":97},{"family":10,"native_errno":97}])
    {
        return Err("frozen V1 actual caller/Unix/Inet native effects differ".into());
    }
    Ok(())
}
fn ordered_object(value: &Value, names: &[&str]) -> VerificationResult<Vec<u8>> {
    let mut out = vec![b'{'];
    for (index, name) in names.iter().enumerate() {
        if index > 0 {
            out.push(b',');
        }
        out.extend(serde_json::to_vec(name).map_err(|e| e.to_string())?);
        out.push(b':');
        let encoded = match *name {
            "authorized_profile" => ordered_object(&value[name], &["id", "semantic_digest"])?,
            "authorization" => ordered_object(
                &value[name],
                &["grant_id", "grant_revision", "approved_plan_digest"],
            )?,
            "ceiling" => ordered_object(
                &value[name],
                &[
                    "direct_socket_authority",
                    "unix_authority",
                    "external_socket_custody",
                    "credential_gains",
                    "mediated_communication",
                ],
            )?,
            "expected_epoch" => ordered_object(&value[name], &["service_instance", "revision"])?,
            "execution_identity" => ordered_object(&value[name], &["kind"])?,
            _ => serde_json::to_vec(&value[name]).map_err(|e| e.to_string())?,
        };
        out.extend(encoded);
    }
    out.push(b'}');
    Ok(out)
}
fn request_json_bytes(request: &Value) -> VerificationResult<Vec<u8>> {
    let mut names = vec![
        "schema_version",
        "workload_plan_digest",
        "authorized_profile",
        "authorization",
        "ceiling",
        "requirements",
        "endpoints",
        "expected_epoch",
    ];
    if request["schema_version"] == 2 {
        names.push("execution_identity");
    }
    ordered_object(request, &names)
}
/// Original public argv and cleared environment produce this frozen native grammar.
/// V1 embeds its original baseline contract; V2 uses its separate outer contract.
pub fn linux_frozen_native_launch(request: &Value) -> VerificationResult<Vec<u8>> {
    linux_frozen_request_digest(request)?;
    fn put(out: &mut Vec<u8>, bytes: &[u8]) {
        out.extend((bytes.len() as u32).to_be_bytes());
        out.extend(bytes);
    }
    let mut out = Vec::new();
    out.extend(3u16.to_be_bytes());
    out.extend(0u64.to_be_bytes());
    put(
        &mut out,
        b"/usr/libexec/memcordon-installed-private-fixture",
    );
    let arguments: Vec<&[u8]> = if request["schema_version"] == 1 {
        vec![b"assert-frozen-baseline"]
    } else {
        vec![b"assert-private-runtime", b"65534", b"65534"]
    };
    out.extend((arguments.len() as u32).to_be_bytes());
    for arg in arguments {
        put(&mut out, arg);
    }
    out.extend(0u32.to_be_bytes());
    out.push(0);
    out.push(1);
    out.extend(0u64.to_be_bytes());
    out.extend([0, 1, 1]);
    for duration in [50u64, 2000, 0, 0] {
        out.extend(duration.to_be_bytes());
    }
    out.extend(5u32.to_be_bytes());
    out.extend([1, 2, 3, 4, 5]);
    if request["schema_version"] == 1 {
        out.push(1);
        put(&mut out, &request_json_bytes(request)?);
    } else {
        out.push(0);
    }
    Ok(out)
}
fn public_request_sha256(request: &Value) -> VerificationResult<(String, String)> {
    let launch = linux_frozen_native_launch(request)?;
    let invocation = sha256(&launch);
    let mut normalized = request.clone();
    normalized["schema_version"] = serde_json::json!(2);
    normalized["execution_identity"] = serde_json::json!({"kind":"preserve-caller"});
    let mut payload =
        b"{\"format\":\"memcordon.private-runtime-request\",\"revision\":1,\"contract\":".to_vec();
    payload.extend(request_json_bytes(&normalized)?);
    payload.extend(b",\"native_launch\":");
    payload.extend(serde_json::to_vec(&launch).map_err(|e| e.to_string())?);
    payload.extend(b",\"attempt_deadline_millis\":null}");
    Ok((sha256(&payload), invocation))
}
pub(crate) fn verify(
    index: &EvidenceIndex,
    record: &CaseRecord,
    e: &LinuxFrozenLegacyEvidence,
    products: &BTreeMap<ProductKey, &ProductObservation>,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let version = match e.key.scenario.as_str() {
        "v1-preserve-caller" => 1,
        "v2-preserve-caller" => 2,
        _ => return Err("frozen legacy scenario differs".into()),
    };
    if e.format != "memcordon.consumer-readiness.linux-frozen-legacy"
        || e.revision != 1
        || e.key != record.key
        || e.key.family != "L-ID-01"
        || e.key.evidence_class != EvidenceClass::InstalledProduct
        || !e.key.target.ends_with("-unknown-linux-gnu")
        || e.run_id != record.run_id
        || e.source_commit != index.source_commit
        || e.source_tree_sha256 != index.source_tree_sha256
    {
        return Err("frozen legacy source/key differs".into());
    }
    let product = products
        .get(&ProductKey {
            target: e.key.target.clone(),
            channel: e
                .key
                .channel
                .clone()
                .ok_or("frozen installed channel absent")?,
        })
        .ok_or("frozen installed product absent")?;
    if product.lifecycle.lease_id != e.lease_id {
        return Err("frozen legacy acquisition lease differs".into());
    }
    let owner = wire::json(custody.bytes(&e.owner)?)?;
    let lease = wire::json(custody.bytes(&e.original_lease)?)?;
    let request = wire::json(custody.bytes(&e.request)?)?;
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
        .find(|c| c.role == "sealed-agent")
        .ok_or("frozen original agent absent")?;
    if lease["format"] != "memcordon.consumer-readiness.linux-lease-owner"
        || lease["revision"] != 1
        || lease["cleanup_agent"] != "/usr/libexec/memcordon-sealed-agent"
        || lease["cleanup_agent_sha256"] != agent.installed_sha256
        || lease["device"].as_u64().is_none_or(|n| n == 0)
        || lease["inode"].as_u64().is_none_or(|n| n == 0)
    {
        return Err("frozen native original lease authority differs".into());
    }
    closed(
        &owner,
        &[
            "format",
            "revision",
            "registry",
            "contract",
            "caller_uid",
            "caller_gid",
            "caller_group",
            "work",
            "output",
            "cli",
            "fixture",
            "launcher",
            "host_network_namespace",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
    )?;
    closed(&owner["host_network_namespace"], &["device", "inode"])?;
    if owner["format"] != "memcordon.linux-frozen-legacy-owner"
        || owner["revision"] != 1
        || owner["caller_uid"] != 65534
        || owner["caller_gid"] != 65534
        || owner["caller_group"]
            .as_u64()
            .filter(|v| *v > 0 && *v <= i32::MAX as u64)
            .is_none()
        || lease["identity"]["run_id"] != e.run_id
        || lease["identity"]["source_commit"] != index.source_commit
        || lease["identity"]["source_tree_sha256"] != index.source_tree_sha256
        || lease["cell"] != serde_json::to_value(&product.key).map_err(|e| e.to_string())?
        || lease["lease_id"] != e.lease_id
        || owner["work_deadline_unix_millis"] != lease["work_deadline_unix_millis"]
        || owner["cleanup_deadline_unix_millis"] != lease["cleanup_deadline_unix_millis"]
    {
        return Err("frozen original native owner/source/cutoff differs".into());
    }
    let owner_suffix = format!("/v{version}/owner.json");
    let prefix = e
        .owner
        .strip_suffix(&owner_suffix)
        .ok_or("frozen owner leaf differs")?;
    let native_output = owner["output"]
        .as_str()
        .ok_or("frozen native output absent")?;
    let installed_prefix = prefix
        .strip_suffix("/frozen-legacy")
        .ok_or("frozen original installed prefix differs")?;
    let cell_prefix = installed_prefix
        .strip_suffix("/installed")
        .ok_or("frozen original installed output leaf differs")?;
    if e.original_lease != format!("{cell_prefix}/lifetime/lease-owner.json")
        || native_output
            != format!(
                "{}/{}",
                lease["artifact_root"]
                    .as_str()
                    .ok_or("frozen original artifact root absent")?,
                installed_prefix
            )
    {
        return Err("frozen native archive redirects acquired output".into());
    }
    for (field, path, original) in [
        ("cli", e.cli.as_str(), "/usr/libexec/memcordon"),
        (
            "fixture",
            e.fixture.as_str(),
            "/usr/libexec/memcordon-installed-private-fixture",
        ),
        ("launcher", e.launcher.as_str(), "/usr/bin/setpriv"),
    ] {
        closed(
            &owner[field],
            &["path", "device", "inode", "length", "sha256", "uid", "mode"],
        )?;
        if owner[field]["path"] != serde_json::json!(original.as_bytes())
            || owner[field]["sha256"] != custody.hash(path)?
            || owner[field]["length"] != custody.bytes(path)?.len() as u64
            || owner[field]["uid"] != 0
            || owner[field]["mode"].as_u64().is_none_or(|v| v & 0o022 != 0)
            || owner[field]["device"].as_u64().is_none_or(|v| v == 0)
            || owner[field]["inode"].as_u64().is_none_or(|v| v == 0)
        {
            return Err("frozen native installed image custody differs".into());
        }
    }
    let cli = product
        .components
        .iter()
        .find(|c| c.role == "public-cli")
        .ok_or("frozen selected CLI absent")?;
    if custody.hash(&e.cli)? != cli.installed_sha256 {
        return Err("frozen actual CLI differs from installed selected product".into());
    }
    validate_activation(e, &owner, product, custody, prefix, version)?;
    linux_frozen_request_digest(&request)?;
    linux_frozen_request_digest(&owner["contract"])?;
    let mut expected = owner["contract"].clone();
    if version == 1 {
        expected["schema_version"] = serde_json::json!(1);
        expected
            .as_object_mut()
            .ok_or("frozen contract object absent")?
            .remove("execution_identity");
    }
    if request != expected {
        return Err("frozen request changed historical fields".into());
    }
    validate_registry(&owner["registry"], &request, custody.hash(&e.fixture)?)?;
    let expected_actions = if version == 1 {
        vec!["result", "plan", "capabilities"]
    } else {
        vec!["result"]
    };
    if e.commands
        .iter()
        .map(|c| c.action.as_str())
        .collect::<Vec<_>>()
        != expected_actions
    {
        return Err("frozen five command applicability differs".into());
    }
    for command in &e.commands {
        validate_command(command, e, &owner, &request, product, custody)?;
    }
    Ok(())
}
fn validate_command(
    c: &LinuxFrozenLegacyCommand,
    e: &LinuxFrozenLegacyEvidence,
    owner: &Value,
    request: &Value,
    product: &ProductObservation,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let version = request["schema_version"]
        .as_u64()
        .ok_or("frozen version absent")?;
    let owner_suffix = format!("/v{version}/owner.json");
    let prefix = e
        .owner
        .strip_suffix(&owner_suffix)
        .ok_or("frozen owner prefix absent")?;
    let row = format!("{prefix}/v{version}/{}", c.action);
    for (path, leaf) in [
        (&c.invocation, "invocation.json"),
        (&c.creation, "creation.json"),
        (&c.exit, "exit.json"),
        (&c.stdout, "stdout.bin"),
        (&c.stderr, "stderr.bin"),
    ] {
        if path != &format!("{row}/{leaf}") {
            return Err("frozen native command peer crosses original row".into());
        }
    }
    let expected_result = if c.action == "result" {
        Some(format!("{row}/result.json"))
    } else {
        None
    };
    if e.request != format!("{prefix}/v{version}/request.json") || c.result != expected_result {
        return Err("frozen original request/result leaf differs".into());
    }
    let invocation = wire::json(custody.bytes(&c.invocation)?)?;
    let creation = wire::json(custody.bytes(&c.creation)?)?;
    let exit = wire::json(custody.bytes(&c.exit)?)?;
    closed(
        &invocation,
        &[
            "format",
            "revision",
            "program",
            "arguments",
            "cwd",
            "environment",
            "started_unix_millis",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
            "budget_millis",
        ],
    )?;
    closed(&creation, &["identity", "kernel_image", "stat"])?;
    closed(
        &exit,
        &[
            "identity",
            "native_status",
            "invocation_sha256",
            "stdout_sha256",
            "stderr_sha256",
            "cli",
            "fixture",
            "launcher",
        ],
    )?;
    let before: HeldProcessIdentity =
        serde_json::from_value(creation["identity"].clone()).map_err(|e| e.to_string())?;
    let after: HeldProcessIdentity =
        serde_json::from_value(exit["identity"].clone()).map_err(|e| e.to_string())?;
    if before.pid == 0
        || before.pid > i32::MAX as u32
        || before.birth == 0
        || before.retirement_observed
        || !after.retirement_observed
        || before.pid != after.pid
        || before.birth != after.birth
        || exit["native_status"] != 0
        || exit["invocation_sha256"] != custody.hash(&c.invocation)?
        || exit["stdout_sha256"] != custody.hash(&c.stdout)?
        || exit["stderr_sha256"] != custody.hash(&c.stderr)?
        || !custody.bytes(&c.stderr)?.is_empty()
    {
        return Err("frozen original PIDFD/native wait/capture custody differs".into());
    }
    let raw_stat = String::from_utf8(bytes(&creation["stat"])?).map_err(|e| e.to_string())?;
    if raw_stat
        .split_whitespace()
        .next()
        .and_then(|v| v.parse::<u32>().ok())
        != Some(before.pid)
        || raw_stat
            .rsplit_once(") ")
            .and_then(|(_, v)| v.split_whitespace().nth(19))
            .and_then(|v| v.parse::<u64>().ok())
            != Some(before.birth)
    {
        return Err("frozen original creation kernel birth differs".into());
    }
    closed(
        &creation["kernel_image"],
        &["device", "inode", "length", "sha256"],
    )?;
    if ![&owner["cli"], &owner["launcher"]].iter().any(|image| {
        ["device", "inode", "length", "sha256"]
            .iter()
            .all(|field| creation["kernel_image"][field] == image[field])
    }) {
        return Err(
            "frozen actual creation executable is not selected CLI or measured setpriv launcher"
                .into(),
        );
    }
    for field in ["cli", "fixture", "launcher"] {
        if exit[field] != owner[field] {
            return Err("frozen installed executable changed across native command".into());
        }
    }
    let started = invocation["started_unix_millis"]
        .as_u64()
        .ok_or("frozen native start clock absent")?;
    let work = owner["work_deadline_unix_millis"]
        .as_u64()
        .ok_or("frozen original cutoff absent")?;
    let cleanup = owner["cleanup_deadline_unix_millis"]
        .as_u64()
        .ok_or("frozen original cleanup cutoff absent")?;
    let budget = invocation["budget_millis"]
        .as_u64()
        .ok_or("frozen native command budget absent")?;
    if invocation["format"] != "memcordon.linux-frozen-legacy-invocation"
        || invocation["revision"] != 1
        || bytes(&invocation["program"])? != b"/usr/bin/setpriv"
        || bytes(&invocation["cwd"])?
            != owner["work"]
                .as_str()
                .ok_or("frozen actual cwd absent")?
                .as_bytes()
        || invocation["environment"] != serde_json::json!([])
        || invocation["work_deadline_unix_millis"] != work
        || invocation["cleanup_deadline_unix_millis"] != cleanup
        || started == 0
        || started >= work
        || cleanup <= work
        || budget == 0
        || budget > 60000
        || budget > work - started
    {
        return Err("frozen native command renews cutoff/environment/cwd".into());
    }
    let native_output = owner["output"].as_str().ok_or("frozen output absent")?;
    let native_request = format!("{native_output}/frozen-legacy/v{version}/request.json");
    let native_report = format!(
        "{}/frozen-v{version}-{}.json",
        owner["work"].as_str().ok_or("frozen cwd absent")?,
        c.action
    );
    let group = owner["caller_group"]
        .as_u64()
        .ok_or("frozen group absent")?;
    let mut arguments = vec![
        "--reuid=65534".to_owned(),
        "--regid=65534".into(),
        format!("--groups={group}"),
        "--bounding-set=-all".into(),
        "--inh-caps=-all".into(),
        "--ambient-caps=-all".into(),
        "--no-new-privs".into(),
        "--".into(),
        "/usr/libexec/memcordon".into(),
    ];
    match c.action.as_str() {
        "result" => arguments.extend([
            "--sealed".into(),
            "--workload-contract".into(),
            native_request,
            "--report-format".into(),
            "result-v1".into(),
            "--report".into(),
            native_report,
            "--".into(),
            "/usr/libexec/memcordon-installed-private-fixture".into(),
            "assert-private-runtime".into(),
            "65534".into(),
            "65534".into(),
        ]),
        "plan" => arguments.extend([
            "plan".into(),
            "--sealed".into(),
            "--plan-format".into(),
            "plan-v1".into(),
            "--workload-contract".into(),
            native_request,
        ]),
        "capabilities" => arguments.extend([
            "doctor".into(),
            "--require".into(),
            "sealed".into(),
            "--capability-format".into(),
            "capabilities-v1".into(),
            "--workload-contract".into(),
            native_request,
        ]),
        _ => return Err("frozen command action differs".into()),
    };
    if version == 1 && c.action == "result" {
        arguments.truncate(arguments.len() - 3);
        arguments.push("assert-frozen-baseline".into());
        let marker = arguments
            .iter()
            .position(|argument| argument == "--sealed")
            .ok_or("frozen sealed argv absent")?;
        arguments.splice(
            marker..marker,
            [
                "--mixed-observation-directory".into(),
                format!("{native_output}/frozen-legacy/v1/result/observations"),
            ],
        );
    }
    if invocation["arguments"]
        != serde_json::json!(arguments.iter().map(|s| s.as_bytes()).collect::<Vec<_>>())
    {
        return Err("frozen native argv changes original public codec/action/caller".into());
    }
    let normalized = request.clone();
    let request_hash = linux_frozen_request_digest(&normalized)?;
    let public = wire::json(custody.bytes(c.result.as_deref().unwrap_or(&c.stdout))?)?;
    if public["format"]
        != match c.action.as_str() {
            "result" => "memcordon.result",
            "plan" => "memcordon.plan",
            _ => "memcordon.capabilities",
        }
        || public["revision"] != 1
        || public["tool"]["name"] != "memcordon"
        || public["tool"]["version"] != product.version
        || c.action == "result" && public["tool"]["os"] != "linux"
    {
        return Err("frozen public output format/tool differs".into());
    }
    if version == 1 {
        let plan = match c.action.as_str() {
            "result" => &public["policy"]["effective"]["workload"]["binding"]["plan"],
            "plan" => &public["workload"]["binding"],
            _ => &public["requirement"]["workload"]["binding"],
        };
        closed(
            &plan["provider"],
            &["generation", "source_commit", "runtime_manifest_sha256"],
        )?;
        if plan["provider"]
            != serde_json::json!({"generation":format!("{}:{}",product.version,product.source_commit),"source_commit":product.source_commit,"runtime_manifest_sha256":custody.hash(&product.runtime_manifest)?})
        {
            return Err(
                "frozen original native provider differs from selected installed manifest".into(),
            );
        }
    }
    if c.action != "result" {
        if !public["private_plan"].is_null() || public["authorizes_launch"] != false {
            return Err("frozen V1 advisory introduces private authority".into());
        }
        let workload = if c.action == "plan" {
            &public["workload"]
        } else {
            if public["requirement"]["met"] != true {
                return Err("frozen V1 qualified capability unavailable".into());
            }
            &public["requirement"]["workload"]
        };
        closed(workload, &["state", "binding", "effective", "pending"])?;
        if workload["state"] != "planned"
            || workload["effective"]
                != serde_json::json!({"profile":"linux-unix-create","ceiling":baseline_ceiling(),"restriction":"linux-unix-only-socket-syscall-filter-alternate-paths-unknown"})
            || workload["pending"]
                != serde_json::json!([
                    "caller-identity",
                    "invocation-identity",
                    "descriptor-custody",
                    "native-controls",
                    "guardian",
                    "current-epoch",
                    "durable-checkpoint"
                ])
        {
            return Err("frozen V1 advisory effective baseline differs".into());
        }
        validate_baseline_plan(&workload["binding"], request, &owner["registry"])?;
        return Ok(());
    }
    closed(
        &public,
        &[
            "format",
            "revision",
            "tool",
            "invocation",
            "policy",
            "attempts",
            "supervision",
            "error",
            "backend",
            "authorization",
            "launch",
            "outcome",
            "cleanup",
            "restart",
            "runtime",
            "private_execution",
            "private_rejection",
            "diagnostics",
            "provider_association",
            "delivery",
        ],
    )?;
    if public["authorization"] != "granted"
        || public["launch"]["state"] != "exec-observed"
        || public["outcome"]
            != serde_json::json!({"kind":"completed","native_termination":{"kind":"exit-code","code":0},"wrapper_status":0})
        || public["cleanup"]["state"] != "complete"
        || public["cleanup"]["direct_child_reaped"] != true
        || public["cleanup"]["workload_empty"] != true
        || public["cleanup"]["outstanding"] != serde_json::json!([])
        || public["cleanup"]["failed_operations"] != serde_json::json!([])
        || !public["error"].is_null()
        || !public["private_rejection"].is_null()
    {
        return Err("frozen executed outcome/retirement differs".into());
    }
    if version == 1 {
        validate_baseline_result(&public, request, owner, custody.bytes(&c.stdout)?, group)?;
        return validate_baseline_exchange(c, e, request, &public, custody);
    }
    let execution = &public["private_execution"];
    closed(
        execution,
        &[
            "terminal",
            "frontend_relay_drained",
            "frontend_interruption",
        ],
    )?;
    let terminal = &execution["terminal"];
    closed(
        terminal,
        &[
            "format",
            "revision",
            "provider",
            "native_abi",
            "attempt_id",
            "request_sha256",
            "admission_metadata",
            "launch",
            "authorization_offset_millis",
            "authorization_monotonic_millis",
            "target_pid",
            "network_namespace",
            "exec_observed",
            "post_exec_descriptor_count",
            "outcome",
            "native_termination",
            "cleanup",
            "account_reservation_retired",
            "namespace_references_closed",
            "error",
        ],
    )?;
    let admission = &terminal["admission_metadata"];
    closed(
        admission,
        &[
            "format",
            "revision",
            "request",
            "request_sha256",
            "invocation_sha256",
            "caller",
            "registry_digest",
            "epoch",
            "admission_nonce",
            "profile_id",
        ],
    )?;
    let (native_request_hash, native_invocation_hash) = public_request_sha256(request)?;
    if execution["frontend_relay_drained"] != true
        || !execution["frontend_interruption"].is_null()
        || terminal["format"] != "memcordon.private-runtime-terminal"
        || terminal["revision"] != 1
        || terminal["request_sha256"] != native_request_hash
        || admission["invocation_sha256"] != native_invocation_hash
        || terminal["launch"] != "exec-observed"
        || terminal["outcome"] != "completed"
        || terminal["native_termination"] != public["outcome"]["native_termination"]
        || terminal["cleanup"] != "complete"
        || terminal["account_reservation_retired"] != true
        || terminal["namespace_references_closed"] != true
        || terminal["exec_observed"] != true
        || terminal["post_exec_descriptor_count"] != 3
        || !terminal["error"].is_null()
        || terminal["target_pid"] != public["launch"]["target_pid"]
        || admission["format"] != "memcordon.private-admission-metadata"
        || admission["revision"] != 1
        || admission["request"] != normalized
        || admission["request_sha256"] != request_hash
        || admission["caller"] != serde_json::json!({"platform":"linux","uid":65534})
        || admission["epoch"] != request["expected_epoch"]
        || admission["profile_id"] != profile()?
        || admission["registry_digest"] != crate::linux_registry::legacy_digest(&owner["registry"])?
    {
        return Err("frozen native terminal original request/caller/epoch/registry differs".into());
    }
    let runtime = &public["runtime"];
    closed(
        runtime,
        &[
            "kind",
            "profile_reference",
            "identity_reference",
            "identity_kind",
            "activation_epoch",
            "native_abi",
            "invocation_sha256",
            "private_namespace_observed",
            "no_socket_at_entry",
            "exec_observed",
            "port_range",
            "unprivileged_port_start",
            "resources_retired",
        ],
    )?;
    if runtime["kind"] != "linux-private-tcp4"
        || runtime["profile_reference"] != "linux-tcp4-private-v1"
        || runtime["identity_reference"] != "caller"
        || runtime["identity_kind"] != "preserve-caller"
        || runtime["activation_epoch"] != request["expected_epoch"]["revision"]
        || runtime["native_abi"] != terminal["native_abi"]
        || runtime["invocation_sha256"] != admission["invocation_sha256"]
        || [
            "private_namespace_observed",
            "no_socket_at_entry",
            "exec_observed",
            "resources_retired",
        ]
        .iter()
        .any(|f| runtime[f] != true)
        || runtime["port_range"] != serde_json::json!([32768, 60999])
        || runtime["unprivileged_port_start"] != 0
    {
        return Err("frozen runtime scope/identity/native epoch differs".into());
    }
    let fixture = wire::json(custody.bytes(&c.stdout)?)?;
    closed(
        &fixture,
        &[
            "format",
            "revision",
            "uid",
            "gid",
            "groups",
            "no_new_privileges",
            "capabilities",
            "entry_fds",
            "network_namespace",
            "ipv6_addresses",
            "tcp_port",
            "tcp_bytes",
            "denied",
        ],
    )?;
    if fixture["format"] != "memcordon.private-native-fixture"
        || fixture["revision"] != 1
        || fixture["uid"] != serde_json::json!([65534, 65534, 65534, 65534])
        || fixture["gid"] != serde_json::json!([65534, 65534, 65534, 65534])
        || fixture["groups"] != serde_json::json!([group])
        || fixture["no_new_privileges"] != true
        || fixture["entry_fds"] != serde_json::json!([0, 1, 2])
        || fixture["ipv6_addresses"] != 0
        || fixture["tcp_bytes"] != "private"
        || fixture["tcp_port"]
            .as_u64()
            .is_none_or(|port| !(32768..=60999).contains(&port))
    {
        return Err("frozen native target caller/TCP/descriptor effect differs".into());
    }
    if fixture["capabilities"]
        != serde_json::json!({"CapInh":"0000000000000000","CapPrm":"0000000000000000","CapEff":"0000000000000000","CapBnd":"0000000000000000","CapAmb":"0000000000000000"})
        || fixture["denied"]
            != serde_json::json!([
                "unix",
                "ipv6",
                "udp",
                "raw",
                "netlink",
                "packet",
                "socketpair",
                "recvmsg",
                "sendmsg",
                "unshare",
                "setns",
                "ptrace",
                "pidfd_getfd",
                "io_uring_setup",
                "setresuid",
                "setresgid",
                "fcntl-async",
                "clone-newnet",
                "clone-detached"
            ])
    {
        return Err("frozen native filter closure differs".into());
    }
    closed(&terminal["network_namespace"], &["device", "inode"])?;
    let namespace = terminal["network_namespace"]["inode"]
        .as_u64()
        .filter(|v| *v > 0)
        .ok_or("frozen native namespace absent")?;
    if fixture["network_namespace"] != format!("net:[{namespace}]")
        || owner["host_network_namespace"]["inode"]
            .as_u64()
            .is_none_or(|v| v == 0 || v == namespace)
    {
        return Err(
            "frozen target native namespace differs from original isolated terminal".into(),
        );
    }
    Ok(())
}

fn validate_baseline_exchange(
    c: &LinuxFrozenLegacyCommand,
    e: &LinuxFrozenLegacyEvidence,
    request: &Value,
    public: &Value,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let request_path = c
        .provider_request
        .as_deref()
        .ok_or("frozen original native request absent")?;
    let terminal_path = c
        .provider_terminal
        .as_deref()
        .ok_or("frozen original native terminal absent")?;
    let admission = &public["policy"]["effective"]["workload"]["binding"];
    let attempt = admission["attempt_id"]
        .as_str()
        .ok_or("frozen original native attempt absent")?;
    let prefix = e
        .owner
        .strip_suffix("/v1/owner.json")
        .ok_or("frozen original owner prefix absent")?;
    if request_path
        != format!("{prefix}/v1/result/observations/{attempt}.legacy-provider-request.bin")
        || terminal_path
            != format!("{prefix}/v1/result/observations/{attempt}.legacy-provider-terminal.bin")
    {
        return Err("frozen original exchange leaf differs".into());
    }
    let attempt_bytes = hex::decode(attempt).map_err(|error| error.to_string())?;
    if attempt_bytes.len() != 16 || attempt_bytes.iter().all(|byte| *byte == 0) {
        return Err("frozen original wire attempt invalid".into());
    }
    let decode = |path: &str, kind: u16| -> VerificationResult<(Vec<u8>, Vec<u8>)> {
        let raw = custody.bytes(path)?;
        if raw.len() < 72
            || raw.len() > 1024 * 1024
            || raw[..2] != 3u16.to_be_bytes()
            || raw[2..4] != kind.to_be_bytes()
            || u32::from_be_bytes(
                raw[4..8]
                    .try_into()
                    .map_err(|_| "frozen frame length invalid")?,
            ) as usize
                != raw.len()
            || raw[24..40] != attempt_bytes
            || raw[8..24].iter().all(|byte| *byte == 0)
            || raw[40..72] != hex::decode(sha256(&raw[72..])).map_err(|error| error.to_string())?
        {
            return Err("frozen original V3 wire frame differs".into());
        }
        Ok((raw[8..24].to_vec(), raw[72..].to_vec()))
    };
    let (nonce, launch) = decode(request_path, 2)?;
    let (returned, payload) = decode(terminal_path, 105)?;
    if nonce != returned || launch != linux_frozen_native_launch(request)? {
        return Err("frozen original request/terminal wire reassociated".into());
    }
    let text = std::str::from_utf8(&payload).map_err(|error| error.to_string())?;
    if !payload.ends_with(b"\n") {
        return Err("frozen original terminal lacks newline".into());
    }
    let mut fields = BTreeMap::new();
    for line in text.lines() {
        let (name, value) = line
            .split_once('=')
            .ok_or("frozen original terminal member malformed")?;
        if name.is_empty() || fields.insert(name, value).is_some() {
            return Err("frozen original terminal member repeated".into());
        }
    }
    for (name, value) in [
        ("schema-version", "2"),
        ("mechanism", "linux-pid-namespace-cgroup-v2"),
        ("status", "0"),
        ("exec-status", "success"),
        ("exec-os-code", "none"),
        (
            "credential-transition-disposition",
            "preserve-caller-envelope",
        ),
        ("memory-limit-exceeded", "false"),
        ("deadline-exceeded", "false"),
    ] {
        if fields.remove(name) != Some(value) {
            return Err("frozen original terminal outcome differs".into());
        }
    }
    if fields
        .remove("policy-revoked")
        .is_some_and(|value| value != "false")
    {
        return Err("frozen original terminal revoked successful attempt".into());
    }
    let enforcement = wire::json(
        fields
            .remove("policy-enforcement")
            .ok_or("frozen original enforcement absent")?
            .as_bytes(),
    )?;
    if enforcement != public["attempts"][0]["policy_enforcement"]
        || fields
            .remove("target-pid")
            .and_then(|value| value.parse::<u64>().ok())
            != public["launch"]["target_pid"].as_u64()
        || fields
            .remove("authorization-offset-millis")
            .and_then(|value| value.parse::<u64>().ok())
            .is_none()
    {
        return Err("frozen original terminal target/enforcement differs".into());
    }
    for name in [
        "caller-envelope-digest",
        "caller-capability-bounding-set-digest",
        "caller-mount-namespace-digest",
    ] {
        digest(
            fields
                .remove(name)
                .ok_or("frozen original caller context digest absent")?,
        )?;
    }
    for name in [
        "spawn-error-reported",
        "assignment-verified",
        "namespaces-verified",
        "target-initial-credentials-verified",
        "initial-provider-capabilities-absent",
        "caller-no-new-privs",
        "target-no-new-privs-matched",
        "target-capability-bounding-set-matched",
        "target-mount-context-derived-from-caller",
        "boundary-independent-of-credentials",
        "descriptors-verified",
        "writable-ancestor-cgroup-denied",
        "parent-namespace-handles-denied",
        "recursive-provider-request-denied",
        "guardian-ready-before-authorization",
        "frontend-loss-authority-verified",
        "cgroup-kill-invoked",
        "cgroup-empty",
        "init-reaped",
        "guardian-reaped",
        "boundary-retired",
    ] {
        if fields.remove(name) != Some("true") {
            return Err("frozen original terminal control/retirement fact differs".into());
        }
    }
    if !fields.is_empty() {
        return Err("frozen original terminal unknown members".into());
    }
    Ok(())
}
