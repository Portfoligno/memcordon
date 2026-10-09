use crate::*;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxMalformedIngressEvidence {
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
    pub activation: String,
    pub original_request: String,
    pub original_source_request: String,
    pub original_frontend: String,
    pub malformed_request: String,
    pub helper_image: String,
    pub invocation: String,
    pub exit: String,
    pub receipt: String,
    pub stdout: String,
    pub stderr: String,
    pub census: String,
    pub account_intent: String,
    pub account_readback: String,
    pub group_readback: String,
}
impl LinuxMalformedIngressEvidence {
    pub(crate) fn artifact_paths(&self) -> Vec<&str> {
        vec![
            &self.owner,
            &self.original_lease,
            &self.acquisition,
            &self.activation,
            &self.original_request,
            &self.original_source_request,
            &self.original_frontend,
            &self.malformed_request,
            &self.helper_image,
            &self.invocation,
            &self.exit,
            &self.receipt,
            &self.stdout,
            &self.stderr,
            &self.census,
            &self.account_intent,
            &self.account_readback,
            &self.group_readback,
        ]
    }
}

fn closed(value: &Value, fields: &[&str]) -> VerificationResult<()> {
    if value.as_object().is_none_or(|object| {
        object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field))
    }) {
        return Err("malformed-ingress raw schema differs".into());
    }
    Ok(())
}
fn bytes(value: &Value) -> VerificationResult<Vec<u8>> {
    serde_json::from_value(value.clone()).map_err(|error| error.to_string())
}
fn frame(
    raw: &Value,
    kind: u16,
    nonce: &[u8],
    attempt: &[u8],
    payload: &[u8],
) -> VerificationResult<()> {
    let mut expected = 4u16.to_be_bytes().to_vec();
    expected.extend(kind.to_be_bytes());
    let total = 72usize
        .checked_add(payload.len())
        .filter(|total| *total <= 1024 * 1024)
        .ok_or("ingress original frame exceeds bound")?;
    expected.extend((total as u32).to_be_bytes());
    expected.extend(nonce);
    expected.extend(attempt);
    expected.extend(hex::decode(sha256(payload)).map_err(|error| error.to_string())?);
    expected.extend(payload);
    if bytes(raw)? != expected {
        return Err("malformed-ingress original native V4 frame reassociated".into());
    }
    Ok(())
}

pub(crate) fn verify(
    index: &EvidenceIndex,
    record: &CaseRecord,
    e: &LinuxMalformedIngressEvidence,
    products: &BTreeMap<ProductKey, &ProductObservation>,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    header(
        &e.format,
        e.revision,
        "memcordon.consumer-readiness.linux-malformed-ingress",
    )?;
    let origin = producer_origin(index, &record.key.target, record.key.channel.as_deref())?;
    if e.key != record.key
        || e.run_id != origin.run_id
        || e.source_commit != index.source_commit
        || e.source_tree_sha256 != index.source_tree_sha256
        || e.key.evidence_class != EvidenceClass::InstalledProduct
        || !e.key.target.ends_with("linux-gnu")
        || e.key.family != "L-ID-01"
        || e.key.scenario != "v3-preserve-caller"
    {
        return Err("malformed-ingress crosses original finite installed scope".into());
    }
    let product = products
        .get(&ProductKey {
            target: e.key.target.clone(),
            channel: e
                .key
                .channel
                .clone()
                .ok_or("ingress installed channel absent")?,
        })
        .copied()
        .ok_or("ingress selected installed product absent")?;
    if e.lease_id != product.lifecycle.lease_id {
        return Err("ingress crosses original installed lease".into());
    }
    for path in e.artifact_paths() {
        custody.bytes(path)?;
    }
    let acquired_parent = std::path::Path::new(&e.acquisition)
        .parent()
        .ok_or("ingress original acquisition directory absent")?;
    if !e.original_lease.ends_with("/lease-owner.json")
        || !e
            .acquisition
            .ends_with("/mixed-cases/owned-resources-acquired.json")
        || acquired_parent.parent() != std::path::Path::new(&e.original_lease).parent()
    {
        return Err("ingress original acquisition paths cross installed scope".into());
    }
    let decode = |path: &str| crate::wire::json(custody.bytes(path)?);
    let owner = decode(&e.owner)?;
    let lease = decode(&e.original_lease)?;
    let acquired = decode(&e.acquisition)?;
    let activation = decode(&e.activation)?;
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
    validate_account(
        &acquired["account"],
        &decode(&e.account_intent)?,
        custody.bytes(&e.account_readback)?,
        custody.bytes(&e.group_readback)?,
        index,
        e,
        &owner,
        &lease,
    )?;
    let agent = product
        .components
        .iter()
        .find(|component| component.role == "sealed-agent")
        .ok_or("ingress installed native agent absent")?;
    if owner["format"] != "memcordon.linux-policy-case-owner"
        || owner["revision"] != 1
        || owner["run_id"] != e.run_id
        || owner["source_commit"] != e.source_commit
        || owner["source_tree_sha256"] != e.source_tree_sha256
        || owner["lease_id"] != e.lease_id
        || owner["cell"] != serde_json::to_value(&product.key).map_err(|error| error.to_string())?
        || lease["identity"] != identity
        || acquired["identity"] != identity
        || lease["format"] != "memcordon.consumer-readiness.linux-lease-owner"
        || lease["revision"] != 1
        || lease["lease_id"] != e.lease_id
        || lease["cell"] != owner["cell"]
        || acquired["cell"] != owner["cell"]
        || acquired["format"] != "memcordon.owned-readiness-resources"
        || acquired["revision"] != 1
        || lease["admin_root"] != owner["admin_root"]
        || acquired["admin_root"] != owner["admin_root"]
        || lease["device"] != owner["admin_root_device"]
        || lease["inode"] != owner["admin_root_inode"]
        || acquired["device"] != lease["device"]
        || acquired["inode"] != lease["inode"]
        || lease["legacy"] != acquired["legacy"]
    {
        return Err(
            "malformed-ingress substitutes original acquisition/source/account authority".into(),
        );
    }
    if lease["cleanup_agent"] != "/usr/libexec/memcordon-sealed-agent"
        || lease["cleanup_agent_sha256"] != agent.installed_sha256
        || ["device", "inode"]
            .iter()
            .any(|field| lease[*field].as_u64().is_none_or(|value| value == 0))
    {
        return Err("ingress original native owner image/root custody absent".into());
    }
    let lifetime: InstalledLifecycleJournal =
        crate::wire::decode(custody.bytes(&product.lifecycle.journal)?)?;
    let roots = lifetime
        .events
        .iter()
        .filter(|event| {
            event.phase == "owned-before-mutation"
                && event.operation == "administrative-staging-created"
                && event.succeeded
        })
        .collect::<Vec<_>>();
    if roots.len() != 1
        || lifetime.run_id != e.run_id
        || lifetime.lease_id != e.lease_id
        || lifetime.source_commit != e.source_commit
        || lifetime.source_tree_sha256 != e.source_tree_sha256
    {
        return Err("ingress original pre-mutation native acquisition journal absent".into());
    }
    let root = decode(&roots[0].native_receipt)?;
    closed(&root, &["path", "device", "inode"])?;
    if root["path"] != lease["admin_root"]
        || root["device"] != lease["device"]
        || root["inode"] != lease["inode"]
    {
        return Err("ingress original native admin root reassociated".into());
    }
    let registry = crate::linux_policy::activation_registry(&activation)?;
    if *registry != owner["baseline_registry"]
        || registry["legacy"] != lease["legacy"]
        || owner["provider"]["generation"] != format!("{}:{}", index.version, index.source_commit)
        || owner["provider"]["source_commit"] != index.source_commit
        || owner["provider"]["runtime_manifest_sha256"]
            != custody.hash(&product.runtime_manifest)?
    {
        return Err("malformed-ingress substitutes original activated policy/provider".into());
    }
    let original = decode(&e.original_request)?;
    closed(
        &original,
        &[
            "format",
            "revision",
            "contract",
            "native_launch",
            "attempt_deadline_millis",
        ],
    )?;
    let source_attempt = e
        .original_source_request
        .rsplit('/')
        .next()
        .and_then(|leaf| leaf.strip_suffix(".provider-request.bin"))
        .filter(|attempt| {
            attempt.len() == 32
                && attempt
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or("ingress original source request native basename absent")?;
    if source_attempt.is_empty()
        || custody.bytes(&e.original_request)? != custody.bytes(&e.original_source_request)?
    {
        return Err(
            "ingress copied request differs from original env-cleared native launch".into(),
        );
    }
    if original["format"] != "memcordon.mixed-runtime-request"
        || original["revision"] != 2
        || original["contract"]["expected_epoch"] != activation["epoch"]
    {
        return Err("malformed-ingress original public request epoch differs".into());
    }
    validate_original_frontend(&original, &decode(&e.original_frontend)?, e, index, custody)?;
    crate::wire::v3_request_digest(&original["contract"])?;
    crate::wire::validate_request(
        &serde_json::to_vec(&original["contract"]).map_err(|error| error.to_string())?,
        &e.key,
        OutcomeOrigin::Target,
    )?;
    validate_baseline(
        &original["contract"],
        registry,
        &acquired,
        &owner,
        &e.key.target,
    )?;
    let mut mutated = original.clone();
    mutated["contract"]["execution_identity"] = serde_json::json!({"kind":"preserve-caller"});
    let malformed = decode(&e.malformed_request)?;
    if malformed != mutated || crate::wire::v3_request_digest(&malformed["contract"]).is_ok() {
        return Err("V3 preserve-caller mutation differs or remains valid".into());
    }
    let receipt = decode(&e.receipt)?;
    closed(
        &receipt,
        &[
            "format",
            "revision",
            "caller_pid",
            "caller_uid",
            "caller_gid",
            "caller_birth",
            "native_image",
            "provider",
            "wire_nonce",
            "attempt",
            "request",
            "response",
            "transport",
        ],
    )?;
    let transport = &receipt["transport"];
    closed(
        transport,
        &[
            "response",
            "provider",
            "nonce",
            "attempt",
            "request_frame",
            "response_frame",
            "peer_pid",
            "peer_uid",
            "peer_gid",
            "peer_stat",
            "peer_pidfd_device",
            "peer_pidfd_inode",
            "peer_pidfd_before_revents",
            "peer_pidfd_after_revents",
        ],
    )?;
    let nonce = bytes(&receipt["wire_nonce"])?;
    let attempt = bytes(&receipt["attempt"])?;
    let submitted = custody.bytes(&e.malformed_request)?;
    let response = bytes(&receipt["response"])?;
    if nonce.len() != 16
        || attempt.len() != 16
        || nonce.iter().all(|byte| *byte == 0)
        || attempt.iter().all(|byte| *byte == 0)
        || receipt["format"] != "memcordon.linux-malformed-ingress-observation"
        || receipt["revision"] != 2
        || receipt["provider"] != owner["provider"]
        || receipt["caller_uid"] != 65534
        || receipt["caller_gid"] != 65534
        || bytes(&receipt["request"])? != submitted
        || transport["provider"] != receipt["provider"]
        || transport["nonce"] != receipt["wire_nonce"]
        || transport["attempt"] != receipt["attempt"]
        || transport["response"] != receipt["response"]
        || transport["peer_pid"]
            .as_u64()
            .is_none_or(|pid| pid == 0 || pid > i32::MAX as u64)
        || transport["peer_uid"] != 0
        || transport["peer_gid"]
            .as_u64()
            .is_none_or(|gid| gid > u32::MAX as u64)
        || ["peer_pidfd_device", "peer_pidfd_inode"]
            .iter()
            .any(|field| transport[*field].as_u64().is_none_or(|value| value == 0))
        || transport["peer_pidfd_before_revents"] != 0
        || transport["peer_pidfd_after_revents"]
            .as_i64()
            .is_none_or(|value| ![0, 1, 16, 17].contains(&value))
    {
        return Err("malformed-ingress native authenticated transport/caller differs".into());
    }
    frame(&transport["request_frame"], 14, &nonce, &attempt, submitted)?;
    frame(
        &transport["response_frame"],
        115,
        &nonce,
        &attempt,
        &response,
    )?;
    let peer = bytes(&transport["peer_stat"])?;
    let peer = std::str::from_utf8(&peer).map_err(|error| error.to_string())?;
    if peer.len() > 65536
        || peer
            .split_once(' ')
            .and_then(|(pid, _)| pid.parse::<u64>().ok())
            != transport["peer_pid"].as_u64()
        || peer
            .rsplit_once(") ")
            .and_then(|(_, rest)| rest.split_whitespace().nth(19))
            .and_then(|birth| birth.parse::<u64>().ok())
            .is_none_or(|birth| birth == 0)
    {
        return Err("ingress original connected peer birth source differs".into());
    }
    let carrier: Value = crate::wire::json(&response)?;
    closed(
        &carrier,
        &[
            "kind",
            "carrier_revision",
            "provider_contract",
            "launch_wire",
            "outcome",
        ],
    )?;
    let outcome = &carrier["outcome"];
    closed(
        outcome,
        &[
            "kind",
            "request_bytes_sha256",
            "reason",
            "detail",
            "allocation",
        ],
    )?;
    closed(&outcome["allocation"], &["authorization", "obligations"])?;
    if carrier["kind"] != "linux-mixed-private"
        || carrier["carrier_revision"] != 2
        || carrier["provider_contract"] != 4
        || carrier["launch_wire"] != 4
        || outcome["kind"] != "rejected-ingress"
        || outcome["reason"] != "malformed-ingress"
        || outcome["request_bytes_sha256"] != sha256(submitted)
        || outcome["detail"]
            .as_str()
            .is_none_or(|detail| detail.is_empty() || detail.len() > 4096)
        || outcome["allocation"]["authorization"] != "never-authorized"
        || outcome["allocation"]["obligations"] != serde_json::json!([])
    {
        return Err(
            "V3 preserve-caller lacks exact native never-authorized malformed refusal".into(),
        );
    }
    validate_command(e, &receipt, &lease, custody)?;
    crate::validate_linux_refusal_census(
        &decode(&e.census)?,
        &identity,
        &owner["cell"],
        &e.lease_id,
        &e.key.scenario,
        &acquired["account"],
        &owner["provider"],
        custody.hash(&e.malformed_request)?,
        custody.hash(&e.receipt)?,
        &hex::encode(attempt),
    )
}

fn validate_original_frontend(
    request: &Value,
    command: &Value,
    e: &LinuxMalformedIngressEvidence,
    index: &EvidenceIndex,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    closed(
        command,
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
    let product = index
        .products
        .iter()
        .find(|product| {
            product.key.target == e.key.target
                && Some(product.key.channel.as_str()) == e.key.channel.as_deref()
        })
        .ok_or("ingress original frontend product absent")?;
    let cli = product
        .components
        .iter()
        .find(|component| component.role == "public-cli")
        .ok_or("ingress original frontend CLI absent")?;
    let args: Vec<Vec<u8>> =
        serde_json::from_value(command["arguments"].clone()).map_err(|error| error.to_string())?;
    let frontend = std::path::Path::new(&e.original_source_request)
        .parent()
        .and_then(std::path::Path::parent)
        .ok_or("ingress original frontend parent absent")?
        .join("frontend-invocation.json");
    if frontend != std::path::Path::new(&e.original_frontend)
        || command["format"] != "memcordon.linux-owned-frontend-invocation"
        || command["revision"] != 1
        || bytes(&command["program"])? != b"/usr/bin/setpriv"
        || command["environment_cleared"] != true
        || command["caller_uid"] != 65534
        || command["caller_gid"] != 65534
        || command["selected_cli_sha256"] != cli.installed_sha256
        || args.len() != 23
    {
        return Err("ingress original request frontend/source differs".into());
    }
    for (position, expected) in [
        (0, "--reuid"),
        (1, "65534"),
        (2, "--regid"),
        (3, "65534"),
        (4, "--clear-groups"),
        (5, "--"),
        (6, "/usr/libexec/memcordon"),
        (7, "+256M"),
        (9, "--sealed"),
        (10, "--workload-contract"),
        (12, "--report-format"),
        (13, "result-v2"),
        (14, "--report"),
        (16, "--mixed-observation-directory"),
        (18, "--image-entrypoint"),
        (19, "owned-readiness"),
        (20, "--"),
        (21, "tcp-http"),
    ] {
        if args[position] != expected.as_bytes() {
            return Err("ingress original qualified frontend recipe differs".into());
        }
    }
    if [11, 15, 17]
        .into_iter()
        .any(|position| !args[position].starts_with(b"/") || args[position].contains(&0))
        || args[22].len() != 64
        || !args[22]
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
    {
        return Err("ingress original qualified frontend operands malformed".into());
    }
    let _ = custody;
    validate_owned_frontend_launch(request, &args)
}

pub(crate) fn validate_owned_frontend_launch(
    request: &Value,
    args: &[Vec<u8>],
) -> VerificationResult<()> {
    if args.len() != 23 {
        return Err("owned original frontend argument cardinality differs".into());
    }
    let deadline = std::str::from_utf8(&args[8])
        .map_err(|error| error.to_string())?
        .strip_prefix('+')
        .and_then(|token| token.strip_suffix("ms"))
        .and_then(|token| token.parse::<u64>().ok())
        .filter(|value| *value > 0 && *value <= 300000)
        .ok_or("ingress original frontend deadline absent")?;
    if request["attempt_deadline_millis"] != deadline {
        return Err("ingress native request budget differs from original frontend".into());
    }
    let launch = bytes(&request["native_launch"])?;
    let mut offset = 0usize;
    fn take<'a>(bytes: &'a [u8], offset: &mut usize, count: usize) -> VerificationResult<&'a [u8]> {
        let end = offset
            .checked_add(count)
            .ok_or("ingress native launch overflow")?;
        let value = bytes
            .get(*offset..end)
            .ok_or("ingress native launch truncated")?;
        *offset = end;
        Ok(value)
    }
    fn number(bytes: &[u8], offset: &mut usize, width: usize) -> VerificationResult<u64> {
        Ok(take(bytes, offset, width)?
            .iter()
            .fold(0, |value, byte| (value << 8) | u64::from(*byte)))
    }
    fn operand<'a>(bytes: &'a [u8], offset: &mut usize) -> VerificationResult<&'a [u8]> {
        let length =
            usize::try_from(number(bytes, offset, 4)?).map_err(|error| error.to_string())?;
        take(bytes, offset, length)
    }
    if number(&launch, &mut offset, 2)? != 3
        || number(&launch, &mut offset, 8)? != 0
        || operand(&launch, &mut offset)? != args[19]
        || number(&launch, &mut offset, 4)? != 2
        || operand(&launch, &mut offset)? != args[21]
        || operand(&launch, &mut offset)? != args[22]
        || number(&launch, &mut offset, 4)? != 0
        || number(&launch, &mut offset, 1)? != 1
        || number(&launch, &mut offset, 8)? != 256 * 1024 * 1024
        || number(&launch, &mut offset, 1)? != 1
        || number(&launch, &mut offset, 8)? != 0
        || take(&launch, &mut offset, 3)? != [0, 1, 2]
    {
        return Err("ingress original native launch argv/environment/limits differ".into());
    }
    for ordinal in 0..4 {
        let value = number(&launch, &mut offset, 8)?;
        if value > 30000 || (ordinal == 0 && value == 0) {
            return Err("ingress original native lifecycle interval differs".into());
        }
    }
    if number(&launch, &mut offset, 4)? != 5
        || take(&launch, &mut offset, 6)? != [1, 2, 3, 4, 5, 0]
        || offset != launch.len()
    {
        return Err("ingress original native descriptor/contract grammar differs".into());
    }
    Ok(())
}

fn validate_account(
    account: &Value,
    intent: &Value,
    passwd: &[u8],
    group: &[u8],
    index: &EvidenceIndex,
    e: &LinuxMalformedIngressEvidence,
    owner: &Value,
    lease: &Value,
) -> VerificationResult<()> {
    validate_owned_account(
        account,
        intent,
        passwd,
        group,
        index,
        &e.key,
        &e.run_id,
        &e.acquisition,
        owner,
        lease,
    )
}

pub(crate) fn validate_owned_account(
    account: &Value,
    intent: &Value,
    passwd: &[u8],
    group: &[u8],
    index: &EvidenceIndex,
    key: &CaseKey,
    run_id: &str,
    acquisition: &str,
    owner: &Value,
    lease: &Value,
) -> VerificationResult<()> {
    closed(
        account,
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
        intent,
        &[
            "format",
            "revision",
            "run_id",
            "cell",
            "account_name",
            "native_absence_verified",
            "creation_attempted",
        ],
    )?;
    let uid = account["uid"]
        .as_u64()
        .filter(|uid| *uid > 0 && *uid <= u32::MAX as u64 && *uid != 65534)
        .ok_or("ingress original managed UID malformed/aliases caller")?;
    let gid = account["gid"]
        .as_u64()
        .filter(|gid| *gid > 0 && *gid <= u32::MAX as u64 && *gid != 65534)
        .ok_or("ingress original managed GID malformed/aliases caller")?;
    #[derive(Serialize)]
    struct Original<'a> {
        run_id: &'a str,
        source_commit: &'a str,
        source_tree_sha256: &'a str,
        version: &'a str,
    }
    let cell = ProductKey {
        target: key.target.clone(),
        channel: key
            .channel
            .clone()
            .ok_or("ingress account original cell absent")?,
    };
    let discriminator = sha256(
        &serde_json::to_vec(&(
            Original {
                run_id,
                source_commit: &index.source_commit,
                source_tree_sha256: &index.source_tree_sha256,
                version: &index.version,
            },
            cell,
        ))
        .map_err(|error| error.to_string())?,
    );
    let discriminator = hex::decode(discriminator).map_err(|error| error.to_string())?;
    let name = format!(
        "mc-ready-{:x}",
        u64::from_le_bytes(
            discriminator[..8]
                .try_into()
                .map_err(|_| "ingress original account discriminator width differs")?
        )
    );
    let root = std::path::Path::new(
        lease["artifact_root"]
            .as_str()
            .ok_or("ingress original account artifact root absent")?,
    )
    .join(
        std::path::Path::new(acquisition)
            .parent()
            .ok_or("ingress original account acquisition scope absent")?,
    );
    for (field, leaf) in [
        ("intent", "exclusive-account-intent.json"),
        ("native_readback", "exclusive-account-getent.bin"),
        ("group_readback", "exclusive-group-getent.bin"),
    ] {
        let submitted = account[field]
            .as_str()
            .ok_or("ingress original account native source path absent")?;
        if std::path::Path::new(submitted) != root.join(leaf) {
            return Err("ingress original account source leaf differs".into());
        }
    }
    if account["name"] != name
        || intent["format"] != "memcordon.owned-readiness-account-intent"
        || intent["revision"] != 1
        || intent["run_id"] != run_id
        || intent["cell"] != owner["cell"]
        || intent["account_name"] != name
        || intent["native_absence_verified"] != true
        || intent["creation_attempted"] != true
        || passwd.len() > 4096
        || group.len() > 4096
        || !passwd.ends_with(b"\n")
    {
        return Err("ingress original native account creation source differs".into());
    }
    let passwd = std::str::from_utf8(passwd).map_err(|error| error.to_string())?;
    let fields = passwd.trim_end_matches('\n').split(':').collect::<Vec<_>>();
    if passwd.lines().count() != 1
        || fields.len() != 7
        || fields[0] != name
        || fields[2] != uid.to_string()
        || fields[3] != gid.to_string()
        || fields[6] != "/usr/sbin/nologin"
        || group != format!("{name}:x:{gid}:\n").as_bytes()
    {
        return Err("ingress original native passwd/group UID scope differs".into());
    }
    Ok(())
}

fn validate_baseline(
    contract: &Value,
    registry: &Value,
    acquired: &Value,
    owner: &Value,
    target: &str,
) -> VerificationResult<()> {
    let identities = registry["execution_identities"]
        .as_array()
        .filter(|rows| rows.len() == 1)
        .ok_or("ingress original managed identity ambiguous")?;
    let layouts = registry["root_layouts"]
        .as_array()
        .filter(|rows| rows.len() == 1)
        .ok_or("ingress original root layout ambiguous")?;
    let grants = registry["grants"]
        .as_array()
        .filter(|rows| rows.len() == 1)
        .ok_or("ingress original policy grant ambiguous")?;
    let identity = &identities[0];
    let layout = &layouts[0];
    let grant = &grants[0];
    let execution = serde_json::json!({"identity":crate::linux_registry::linux_identity_reference(identity)?,"exclusive_use_policy":identity["exclusive_use_policy"]});
    if identity["uid"] != acquired["account"]["uid"]
        || identity["gid"] != acquired["account"]["gid"]
        || identity["enabled"] != true
        || identity["identity_id"] != "owned-readiness-identity"
        || identity["reservation_key"] != "owned-readiness-reservation"
        || identity["supplementary_groups"] != serde_json::json!([])
        || identity["exclusive_use_policy"]
            != crate::linux_images::owned_exclusive_declaration_reference(
                &acquired["identity"],
                &owner["cell"],
                &acquired["account"],
            )?
        || contract["execution_identity"] != execution
        || contract["authorized_profile"]
            != crate::linux_registry::linux_combined_profile_reference()
        || contract["runtime_image"]
            != crate::linux_image_reference(&acquired["images"]["runtime"], target)?
        || contract["input_image"]
            != crate::linux_image_reference(&acquired["images"]["input"], target)?
        || layout["layout_id"] != "owned-readiness-root"
        || layout["runtime_image"] != contract["runtime_image"]
        || layout["input_image"] != contract["input_image"]
        || layout["writable_roots"]
            != serde_json::json!([{"id":"work","path":"work","byte_limit":16u64*1024*1024*1024,"generated_execution":true}])
        || layout["output_files"] != serde_json::json!([])
        || contract["root_layout"] != crate::linux_registry::linux_root_layout_reference(layout)?
        || contract["requirements"]
            != serde_json::json!([{"kind":"tcp_listener","id":"tcp","local_port":{"kind":"kernel_assigned"},"peer":{"kind":"dynamic_loopback_within_this_attempt"}}])
        || contract["launch"]
            != serde_json::json!({"entrypoint":"owned-readiness","working_directory":"work"})
        || grant["id"] != "owned-readiness-grant"
        || grant["revision"] != 1
        || grant["enabled"] != true
        || grant["callers"] != serde_json::json!([{"platform":"linux","uid":65534}])
        || contract["authorization"]
            != serde_json::json!({"grant_id":"owned-readiness-grant","grant_revision":1,"approved_plan_digest":contract["workload_plan_digest"]})
        || grant["approved_plans"] != serde_json::json!([contract["workload_plan_digest"]])
    {
        return Err(
            "malformed ingress substitutes original baseline grant/image/root/identity semantics"
                .into(),
        );
    }
    for field in [
        "execution_identity",
        "runtime_image",
        "input_image",
        "root_layout",
    ] {
        if grant[field] != contract[field] {
            return Err("ingress original grant reference differs".into());
        }
    }
    if grant["profile"] != contract["authorized_profile"]
        || contract["workload_plan_digest"] != tcp_plan_digest(contract)?
    {
        return Err("ingress original approved plan digest differs".into());
    }
    Ok(())
}

fn tcp_plan_digest(contract: &Value) -> VerificationResult<String> {
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Reference {
        id: String,
        digest: String,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Execution {
        identity: Reference,
        exclusive_use_policy: Reference,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
    enum Port {
        KernelAssigned,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
    enum Peer {
        DynamicLoopbackWithinThisAttempt,
    }
    #[derive(Serialize, Deserialize)]
    #[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
    enum Requirement {
        TcpListener {
            id: String,
            local_port: Port,
            peer: Peer,
        },
    }
    let reference = |name: &str| {
        serde_json::from_value::<Reference>(contract[name].clone())
            .map_err(|error| error.to_string())
    };
    let execution: Execution = serde_json::from_value(contract["execution_identity"].clone())
        .map_err(|error| error.to_string())?;
    let requirements: Vec<Requirement> = serde_json::from_value(contract["requirements"].clone())
        .map_err(|error| error.to_string())?;
    Ok(sha256(
        &serde_json::to_vec(&(
            reference("runtime_image")?,
            reference("input_image")?,
            reference("root_layout")?,
            execution,
            requirements,
        ))
        .map_err(|error| error.to_string())?,
    ))
}

fn validate_command(
    e: &LinuxMalformedIngressEvidence,
    receipt: &Value,
    lease: &Value,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let command: Value = crate::wire::json(custody.bytes(&e.invocation)?)?;
    let exit: Value = crate::wire::json(custody.bytes(&e.exit)?)?;
    closed(
        &command,
        &[
            "format",
            "revision",
            "program",
            "arguments",
            "environment_cleared",
            "helper",
            "helper_sha256",
            "caller_uid",
            "caller_gid",
            "cwd",
            "budget_millis",
            "started_unix_millis",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
    )?;
    closed(
        &exit,
        &[
            "format",
            "revision",
            "creation",
            "retirement",
            "raw_wait_status",
            "native_exit",
            "signal",
            "invocation_sha256",
            "stdout_sha256",
            "stderr_sha256",
        ],
    )?;
    let before: HeldProcessIdentity =
        serde_json::from_value(exit["creation"].clone()).map_err(|error| error.to_string())?;
    let after: HeldProcessIdentity =
        serde_json::from_value(exit["retirement"].clone()).map_err(|error| error.to_string())?;
    let arguments: Vec<Vec<u8>> =
        serde_json::from_value(command["arguments"].clone()).map_err(|error| error.to_string())?;
    let cwd = bytes(&command["cwd"])?;
    let cwd = std::str::from_utf8(&cwd).map_err(|error| error.to_string())?;
    let original_scope = std::path::Path::new(
        lease["artifact_root"]
            .as_str()
            .ok_or("ingress original native artifact root absent")?,
    )
    .join(
        std::path::Path::new(&e.acquisition)
            .parent()
            .ok_or("ingress original acquired directory absent")?,
    )
    .join("policy-cases");
    let started = command["started_unix_millis"]
        .as_u64()
        .ok_or("ingress original native start absent")?;
    let work = lease["work_deadline_unix_millis"]
        .as_u64()
        .ok_or("ingress original work cutoff absent")?;
    let cleanup = lease["cleanup_deadline_unix_millis"]
        .as_u64()
        .ok_or("ingress original cleanup cutoff absent")?;
    if command["format"] != "memcordon.linux-malformed-ingress-invocation"
        || command["revision"] != 2
        || bytes(&command["program"])? != b"/usr/bin/setpriv"
        || command["environment_cleared"] != true
        || command["caller_uid"] != 65534
        || command["caller_gid"] != 65534
        || command["helper_sha256"] != custody.hash(&e.helper_image)?
        || arguments.len() != 12
        || arguments[..6]
            != [
                b"--reuid".to_vec(),
                b"65534".to_vec(),
                b"--regid".to_vec(),
                b"65534".to_vec(),
                b"--clear-groups".to_vec(),
                b"--".to_vec(),
            ]
        || arguments[6]
            != command["helper"]
                .as_str()
                .ok_or("ingress selected helper path absent")?
                .as_bytes()
        || arguments[7] != b"consumer-readiness-malformed-ingress"
        || arguments[8] != b"--request"
        || arguments[10] != b"--output"
        || arguments[9] != format!("{cwd}/malformed-provider-request.bin").as_bytes()
        || arguments[11] != format!("{cwd}/caller-observation/native-ingress.json").as_bytes()
        || !std::path::Path::new(cwd).starts_with(
            lease["artifact_root"]
                .as_str()
                .ok_or("ingress original artifact root absent")?,
        )
        || std::path::Path::new(cwd) != original_scope.join("v3-preserve-caller")
        || !std::path::Path::new(&e.original_source_request).starts_with(
            std::path::Path::new(&e.acquisition)
                .parent()
                .ok_or("ingress original source scope absent")?
                .join("policy-cases"),
        )
        || !cwd.starts_with('/')
        || cwd
            .split('/')
            .skip(1)
            .any(|component| component.is_empty() || component == "." || component == "..")
        || started == 0
        || started >= work
        || cleanup <= work
        || command["work_deadline_unix_millis"] != work
        || command["cleanup_deadline_unix_millis"] != cleanup
        || command["budget_millis"].as_u64().is_none_or(|budget| {
            budget == 0 || budget > 60000 || budget > work.saturating_sub(started)
        })
        || before.pid == 0
        || before.pid > i32::MAX as u32
        || before.birth == 0
        || before.retirement_observed
        || !after.retirement_observed
        || before.pid != after.pid
        || before.birth != after.birth
        || receipt["caller_pid"] != before.pid
        || receipt["caller_birth"] != before.birth
        || exit["format"] != "memcordon.linux-malformed-ingress-exit"
        || exit["revision"] != 1
        || exit["raw_wait_status"] != 0
        || exit["native_exit"] != 0
        || !exit["signal"].is_null()
        || exit["invocation_sha256"] != custody.hash(&e.invocation)?
        || exit["stdout_sha256"] != custody.hash(&e.stdout)?
        || exit["stderr_sha256"] != custody.hash(&e.stderr)?
        || !custody.bytes(&e.stdout)?.is_empty()
        || !custody.bytes(&e.stderr)?.is_empty()
    {
        return Err("malformed-ingress original native helper command/wait reassociated".into());
    }
    closed(
        &receipt["native_image"],
        &["device", "inode", "length", "sha256"],
    )?;
    if receipt["native_image"]["sha256"] != custody.hash(&e.helper_image)?
        || receipt["native_image"]["length"] != custody.bytes(&e.helper_image)?.len() as u64
        || ["device", "inode"].iter().any(|field| {
            receipt["native_image"][*field]
                .as_u64()
                .is_none_or(|value| value == 0)
        })
    {
        return Err("ingress native running helper image differs".into());
    }
    Ok(())
}
