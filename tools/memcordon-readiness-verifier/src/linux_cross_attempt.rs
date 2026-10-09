//! Concurrent original abstract listeners belong to two independently held attempts.
use crate::*;
use serde::Serialize;
use serde_json::{Value, json};

fn closed(value: &Value, fields: &[&str]) -> VerificationResult<()> {
    if value.as_object().is_none_or(|object| {
        object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field))
    }) {
        return Err("cross-attempt original native schema differs".into());
    }
    Ok(())
}

fn plan(contract: &Value, peer: bool) -> VerificationResult<String> {
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
    #[serde(tag = "kind", rename_all = "snake_case")]
    enum Requirement<'a> {
        UnixAbstractStream { id: &'a str },
        ExpectedDenial { id: &'a str, operation: &'a str },
    }
    fn make(value: &Value) -> Bound<'_> {
        Bound {
            id: &value["id"],
            digest: &value["digest"],
        }
    }
    let requirements = if peer {
        vec![Requirement::UnixAbstractStream {
            id: "peer-abstract",
        }]
    } else {
        vec![
            Requirement::UnixAbstractStream { id: "own-abstract" },
            Requirement::ExpectedDenial {
                id: "other-attempt-denial",
                operation: "other_attempt",
            },
        ]
    };
    if contract["requirements"] != json!(requirements) {
        return Err("cross-attempt original finite source requirements differ".into());
    }
    let identity = Identity {
        identity: make(&contract["execution_identity"]["identity"]),
        exclusive_use_policy: make(&contract["execution_identity"]["exclusive_use_policy"]),
    };
    Ok(sha256(
        &serde_json::to_vec(&(
            make(&contract["runtime_image"]),
            make(&contract["input_image"]),
            make(&contract["root_layout"]),
            identity,
            requirements,
        ))
        .map_err(|error| error.to_string())?,
    ))
}

fn policy_command(
    command: &Value,
    exit: &Value,
    command_bytes: &[u8],
    stdout: &[u8],
    stderr: &[u8],
    policy: &[u8],
    agent: &str,
) -> VerificationResult<()> {
    closed(
        command,
        &[
            "format",
            "revision",
            "program",
            "arguments",
            "cwd",
            "environment_cleared",
            "budget_millis",
            "started_unix_millis",
            "deadline_unix_millis",
            "program_sha256",
            "program_device",
            "program_inode",
            "policy_sha256",
        ],
    )?;
    closed(
        exit,
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
    closed(&exit["creation"], &["pid", "birth", "image"])?;
    closed(
        &exit["retirement"],
        &[
            "pid",
            "birth",
            "parent_pid",
            "parent_birth",
            "retirement_observed",
        ],
    )?;
    closed(
        &exit["creation"]["image"],
        &["device", "inode", "length", "sha256"],
    )?;
    let arguments: Vec<Vec<u8>> =
        serde_json::from_value(command["arguments"].clone()).map_err(|error| error.to_string())?;
    let program: Vec<u8> =
        serde_json::from_value(command["program"].clone()).map_err(|error| error.to_string())?;
    let cwd: Vec<u8> =
        serde_json::from_value(command["cwd"].clone()).map_err(|error| error.to_string())?;
    if command["format"] != "memcordon.linux-cross-policy-command"
        || command["revision"] != 1
        || program != b"/usr/libexec/memcordon-sealed-agent"
        || command["program_sha256"] != agent
        || command["policy_sha256"] != sha256(policy)
        || command["environment_cleared"] != true
        || command["budget_millis"]
            .as_u64()
            .is_none_or(|budget| budget == 0 || budget > 60000)
        || arguments.len() != 5
        || arguments[..4]
            != [
                b"package".to_vec(),
                b"policy".to_vec(),
                b"apply".to_vec(),
                b"--file".to_vec(),
            ]
        || !arguments[4].starts_with(b"/")
        || arguments[4].contains(&0)
        || arguments[4]
            .split(|byte| *byte == b'/')
            .any(|part| part == b"." || part == b"..")
        || !cwd.starts_with(b"/")
        || cwd.contains(&0)
        || exit["format"] != "memcordon.linux-cross-policy-exit"
        || exit["revision"] != 1
        || exit["raw_wait_status"] != 0
        || exit["native_exit"] != 0
        || !exit["signal"].is_null()
        || exit["retirement"]["retirement_observed"] != true
        || ["pid", "birth"].iter().any(|field| {
            exit["creation"][*field]
                .as_u64()
                .is_none_or(|value| value == 0)
                || exit["creation"][*field] != exit["retirement"][*field]
        })
        || exit["invocation_sha256"] != sha256(command_bytes)
        || exit["stdout_sha256"] != sha256(stdout)
        || exit["stderr_sha256"] != sha256(stderr)
        || exit["creation"]["image"]["sha256"] != agent
        || exit["creation"]["image"]["device"] != command["program_device"]
        || exit["creation"]["image"]["inode"] != command["program_inode"]
        || ["device", "inode", "length"].iter().any(|field| {
            exit["creation"]["image"][*field]
                .as_u64()
                .is_none_or(|value| value == 0)
        })
    {
        return Err("cross-attempt original policy Child/kernel/PIDFD/wait/captures differ".into());
    }
    Ok(())
}

pub(crate) fn validate(
    behavior: &FixtureBehavior,
    semantic: &SemanticObservation,
    native: &NativeObservation,
    evidence: &CaseEvidence,
    index: &EvidenceIndex,
    custody: &custody::Custody,
) -> VerificationResult<behavior::Facts> {
    if semantic.key.family != "L-ISO-03"
        || semantic.key.scenario != "other-attempt-abstract"
        || semantic.key.evidence_class != EvidenceClass::InstalledProduct
        || !semantic.key.target.ends_with("linux-gnu")
    {
        return Err("cross-attempt decoder outside finite original scope".into());
    }
    let peers = behavior
        .peer_artifacts
        .iter()
        .filter(|peer| peer.role == "other-attempt-abstract-canary")
        .collect::<Vec<_>>();
    if peers.len() != 1 {
        return Err("cross-attempt original concurrent peer canary absent/ambiguous".into());
    }
    let canary: Value = wire::decode(custody.bytes(&peers[0].path)?)?;
    let mut closed_canary = canary.clone();
    for field in ["original_lease", "original_acquisition"] {
        if closed_canary
            .as_object_mut()
            .ok_or("cross canary is not object")?
            .remove(field)
            .is_none()
        {
            return Err(format!("cross original scope absent: {field}"));
        }
    }
    closed(
        &closed_canary,
        &[
            "format",
            "revision",
            "run_id",
            "lease_id",
            "cell",
            "challenge",
            "name",
            "peer_account",
            "peer_account_intent",
            "peer_account_passwd",
            "peer_account_group",
            "prior_registry",
            "activation",
            "activation_policy",
            "activation_invocation",
            "activation_exit",
            "activation_stderr",
            "restoration",
            "restoration_policy",
            "restoration_invocation",
            "restoration_exit",
            "restoration_stderr",
            "peer_frontend_invocation",
            "peer_frontend_exit",
            "peer_request",
            "peer_prepared",
            "peer_native",
            "peer_result",
            "peer_retirement",
            "held_peer",
            "held_peer_after",
            "target_native",
            "listener",
            "peer_collection_root",
            "target_collection_root",
            "peer_case",
            "peer_account_creation",
            "peer_account_retirement",
            "cross_owner",
            "prior_activation",
            "original_contract",
        ],
    )?;
    let path = |field: &str| -> VerificationResult<&str> {
        canary[field]
            .as_str()
            .ok_or_else(|| format!("cross-attempt original archive reference absent: {field}"))
    };
    let decode =
        |field: &str| -> VerificationResult<Value> { wire::decode(custody.bytes(path(field)?)?) };
    let challenge = custody.bytes(&semantic.challenge)?;
    let product = index
        .products
        .iter()
        .find(|product| {
            product.key.target == semantic.key.target
                && Some(product.key.channel.as_str()) == semantic.key.channel.as_deref()
        })
        .ok_or("cross-attempt selected original installed product absent")?;
    if canary["format"] != "memcordon.linux-other-attempt-abstract-canary"
        || canary["revision"] != 1
        || canary["run_id"] != native.run_id
        || canary["lease_id"].as_str() != native.lease_id.as_deref()
        || canary["cell"] != json!(product.key)
        || canary["challenge"] != hex::encode(challenge)
        || native.target_status != Some(0)
        || native.origin != OutcomeOrigin::Target
    {
        return Err("cross-attempt substitutes original native cell/challenge/completion".into());
    }
    let target_binding: Value = wire::decode(
        custody.bytes(
            behavior
                .native_binding
                .as_deref()
                .ok_or("cross-attempt original target binding absent")?,
        )?,
    )?;
    let peer_binding = decode("peer_native")?;
    let peer_prepared = decode("peer_prepared")?;
    let peer_request = decode("peer_request")?;
    if canary["held_peer"] != peer_binding["target"]
        || canary["held_peer_after"] != canary["held_peer"]
        || canary["target_native"] != target_binding["target"]
        || canary["held_peer"]["process_id"] == canary["target_native"]["process_id"]
        || canary["held_peer"]["network"] == canary["target_native"]["network"]
        || peer_binding["attempt_id"] == target_binding["attempt_id"]
        || peer_prepared["admission"]["admission_nonce"]
            == wire::json(
                custody.bytes(
                    evidence
                        .prepared_observation
                        .as_deref()
                        .ok_or("cross-attempt target original prepared absent")?,
                )?,
            )?["admission"]["admission_nonce"]
    {
        return Err("cross-attempt held original listener aliases target namespace/attempt".into());
    }
    let peer_case: CaseEvidence = wire::decode(custody.bytes(path("peer_case")?)?)?;
    let mut expected = semantic.key.clone();
    expected.scenario = "own-abstract-positive".into();
    if peer_case.key != expected
        || peer_case.run_id != evidence.run_id
        || peer_case.source_commit != evidence.source_commit
        || peer_case.source_tree_sha256 != evidence.source_tree_sha256
        || peer_case.provider_request.as_deref() != Some(path("peer_request")?)
        || peer_case.raw_result.as_deref() != Some(path("peer_result")?)
        || custody.bytes(
            peer_case
                .prepared_observation
                .as_deref()
                .ok_or("cross-attempt peer original prepared absent")?,
        )? != custody.bytes(path("peer_prepared")?)?
        || peer_case.prepared_native_receipt.as_deref() != Some(path("peer_native")?)
    {
        return Err("cross-attempt peer complete original record differs".into());
    }
    let peer_semantic: SemanticObservation =
        wire::decode(custody.bytes(&peer_case.semantic_observation)?)?;
    if peer_semantic.fixture_behavior.as_ref().is_none_or(|value| {
        value
            .peer_artifacts
            .iter()
            .any(|peer| peer.role == "other-attempt-abstract-canary")
    }) {
        return Err("cross-attempt original peer recursively adopts target canary".into());
    }
    let peer_record = CaseRecord {
        key: expected,
        state: CaseState::Passed,
        run_id: peer_case.run_id.clone(),
        reason: None,
        evidence: Some(path("peer_case")?.into()),
    };
    let products = index
        .products
        .iter()
        .map(|product| (product.key.clone(), product))
        .collect();
    let builds = index
        .component_builds
        .iter()
        .map(|build| (build.target.clone(), build))
        .collect();
    crate::verify_record(index, &peer_record, &products, &builds, custody)?;
    let family = decode("peer_retirement")?;
    closed(
        &family,
        &[
            "format",
            "revision",
            "run_id",
            "lease_id",
            "attempt_id",
            "target",
            "namespace_init",
            "guardian",
            "descendants",
            "namespace_members",
            "aggregate_empty",
        ],
    )?;
    if family["format"] != "memcordon.linux-held-family-retirement"
        || family["revision"] != 1
        || family["run_id"] != native.run_id
        || family["lease_id"].as_str() != native.lease_id.as_deref()
        || family["attempt_id"] != peer_binding["attempt_id"]
        || family["aggregate_empty"] != true
        || family["descendants"] != json!([])
        || family["namespace_members"] != json!([])
    {
        return Err("cross-attempt original peer complete native family closure differs".into());
    }
    for role in ["target", "namespace_init", "guardian"] {
        let retired: HeldProcessIdentity =
            serde_json::from_value(family[role].clone()).map_err(|error| error.to_string())?;
        if !retired.retirement_observed
            || family[role]["pid"] != peer_prepared[role]["pid"]
            || family[role]["birth"] != peer_prepared[role]["birth"]
        {
            return Err(
                "cross-attempt original peer namespace family settlement substitutes native birth"
                    .into(),
            );
        }
    }
    crate::linux_cross_account::validate(&canary, index, &semantic.key, custody)?;
    let cli = product
        .components
        .iter()
        .find(|component| component.role == "public-cli")
        .ok_or("cross-attempt original CLI absent")?;
    let frontend = decode("peer_frontend_invocation")?;
    closed(
        &frontend,
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
    let args: Vec<Vec<u8>> =
        serde_json::from_value(frontend["arguments"].clone()).map_err(|error| error.to_string())?;
    let program: Vec<u8> =
        serde_json::from_value(frontend["program"].clone()).map_err(|error| error.to_string())?;
    let fixed = [
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
        (21, "own-abstract-held"),
    ];
    if frontend["format"] != "memcordon.linux-owned-frontend-invocation"
        || frontend["revision"] != 1
        || program != b"/usr/bin/setpriv"
        || args.len() != 23
        || fixed
            .into_iter()
            .any(|(index, value)| args[index] != value.as_bytes())
        || args[22] != hex::encode(challenge).as_bytes()
        || frontend["environment_cleared"] != true
        || frontend["caller_uid"] != 65534
        || frontend["caller_gid"] != 65534
        || frontend["selected_cli_sha256"] != cli.installed_sha256
    {
        return Err("cross-attempt original peer public frontend source differs".into());
    }
    let deadline = std::str::from_utf8(&args[8]).map_err(|error| error.to_string())?;
    let budget = deadline
        .strip_prefix('+')
        .and_then(|value| value.strip_suffix("ms"))
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0 && *value <= 30000)
        .ok_or("cross-attempt original peer native deadline absent")?;
    if deadline != format!("+{budget}ms") || peer_request["attempt_deadline_millis"] != budget {
        return Err("cross-attempt original peer native deadline differs from ingress".into());
    }
    crate::linux_ingress::validate_owned_frontend_launch(&peer_request, &args)?;
    let peer_result = decode("peer_result")?;
    let public = json!({"syntax":"plus-budgets-v1","budget_tokens":[{"kind":"memory","token":"+256M"},{"kind":"time","token":deadline}],"memory_token":"+256M","deadline_token":deadline,"argv":[{"display":"owned-readiness","raw":null},{"display":"own-abstract-held","raw":null},{"display":hex::encode(challenge),"raw":null}]});
    if peer_result["invocation"] != public {
        return Err("cross-attempt original peer parser argv differs".into());
    }
    let frontend_exit = decode("peer_frontend_exit")?;
    closed(
        &frontend_exit,
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
    let peer_root = path("peer_collection_root")?;
    let stdout = crate::linux_path::join(peer_root, "stdout.bin");
    let stderr = crate::linux_path::join(peer_root, "stderr.bin");
    if frontend_exit["format"] != "memcordon.linux-policy-frontend-exit"
        || frontend_exit["revision"] != 1
        || frontend_exit["process_id"] != peer_binding["caller"]["process_id"]
        || frontend_exit["process_birth"] != peer_binding["caller"]["birth"]
        || frontend_exit["raw_wait_status"] != 0
        || frontend_exit["native_exit"] != 0
        || !frontend_exit["signal"].is_null()
        || frontend_exit["invocation_sha256"] != custody.hash(path("peer_frontend_invocation")?)?
        || frontend_exit["stdout_sha256"] != custody.hash(&stdout)?
        || frontend_exit["stderr_sha256"] != custody.hash(&stderr)?
    {
        return Err("cross-attempt original peer Child wait/captures differ".into());
    }
    let activation = decode("activation")?;
    let prior = decode("prior_registry")?;
    let restoration = decode("restoration")?;
    let owner = decode("cross_owner")?;
    let mut closed_owner = owner.clone();
    for field in [
        "original_lease",
        "original_acquisition",
        "work_deadline_unix_millis",
        "cleanup_deadline_unix_millis",
    ] {
        if closed_owner
            .as_object_mut()
            .ok_or("cross owner not object")?
            .remove(field)
            .is_none()
        {
            return Err(format!("cross original owner scope absent: {field}"));
        }
    }
    closed(
        &closed_owner,
        &[
            "format",
            "revision",
            "identity",
            "cell",
            "lease_id",
            "acquisition_output",
            "protected_output",
            "original_registry_sha256",
            "primary_account",
        ],
    )?;
    let original = decode("original_contract")?;
    let initial = decode("prior_activation")?;
    let lease = decode("original_lease")?;
    let acquisition = decode("original_acquisition")?;
    let artifact_root = lease["artifact_root"]
        .as_str()
        .ok_or("cross original artifact root absent")?;
    for field in ["original_lease", "original_acquisition"] {
        if owner[field] != json!(crate::linux_path::join(artifact_root, path(field)?)) {
            return Err("cross original owner source authority file differs".into());
        }
    }
    for field in ["work_deadline_unix_millis", "cleanup_deadline_unix_millis"] {
        if owner[field] != lease[field] {
            return Err("cross original owner cutoff copy differs".into());
        }
    }
    let account_parent = crate::linux_path::parent(path("peer_account_intent")?)
        .ok_or("cross archived account parent absent")?;
    let native_account_parent = crate::linux_path::join(artifact_root, &account_parent);
    if lease["format"] != "memcordon.consumer-readiness.linux-lease-owner"
        || lease["identity"] != owner["identity"]
        || lease["cell"] != owner["cell"]
        || lease["lease_id"] != owner["lease_id"]
        || acquisition["identity"] != owner["identity"]
        || acquisition["cell"] != owner["cell"]
        || acquisition["account"] != owner["primary_account"]
        || acquisition["admin_root"] != lease["admin_root"]
        || owner["acquisition_output"].as_str() != Some(native_account_parent.as_str())
        || !crate::linux_path::parent(
            canary["peer_account"]["intent"]
                .as_str()
                .ok_or("cross native account intent absent")?,
        )
        .is_some_and(|parent| crate::linux_path::equivalent(&parent, &native_account_parent))
        || !{
            let ancestors = crate::linux_path::ancestors(
                owner["protected_output"]
                    .as_str()
                    .ok_or("cross protected output absent")?,
            );
            let admin_root = lease["admin_root"]
                .as_str()
                .ok_or("cross original admin root absent")?;
            ancestors
                .iter()
                .any(|ancestor| crate::linux_path::equivalent(ancestor, admin_root))
        }
    {
        return Err("cross original lease/acquisition/native account scope differs".into());
    }
    if owner["format"] != "memcordon.linux-cross-attempt-owner"
        || owner["revision"] != 1
        || owner["identity"]
            != json!({"run_id":native.run_id,"source_commit":index.source_commit,"source_tree_sha256":index.source_tree_sha256,"version":index.version})
        || owner["cell"] != canary["cell"]
        || owner["lease_id"] != canary["lease_id"]
        || owner["original_registry_sha256"] != custody.hash(path("prior_registry")?)?
        || linux_policy::activation_registry(&initial)? != &prior
        || original["expected_epoch"] != initial["epoch"]
        || initial["epoch"]["service_instance"] != activation["epoch"]["service_instance"]
        || initial["epoch"]["revision"].as_u64() >= activation["epoch"]["revision"].as_u64()
    {
        return Err("cross-attempt original acquired owner/baseline epoch differs".into());
    }
    if linux_policy::activation_registry(&restoration)? != &prior
        || restoration["epoch"]["service_instance"] != activation["epoch"]["service_instance"]
        || restoration["epoch"]["revision"].as_u64() <= activation["epoch"]["revision"].as_u64()
    {
        return Err("cross-attempt original registry restoration/epoch differs".into());
    }
    let registry = linux_policy::activation_registry(&activation)?;
    let target_request: Value = wire::decode(
        custody.bytes(
            evidence
                .provider_request
                .as_deref()
                .ok_or("cross-attempt original target provider request absent")?,
        )?,
    )?;
    let target = &target_request["contract"];
    let peer = &peer_request["contract"];
    let mut expected_target = original.clone();
    for field in [
        "requirements",
        "workload_plan_digest",
        "authorization",
        "expected_epoch",
    ] {
        expected_target[field] = target[field].clone();
    }
    if expected_target != *target
        || target["authorization"]["grant_id"] != original["authorization"]["grant_id"]
        || target["authorization"]["grant_revision"] != original["authorization"]["grant_revision"]
    {
        return Err(
            "cross-attempt target changes original source authority beyond exact plan/epoch".into(),
        );
    }
    for field in [
        "runtime_image",
        "input_image",
        "root_layout",
        "launch",
        "authorized_profile",
        "ceiling",
    ] {
        if peer[field] != original[field] {
            return Err("cross-attempt peer changes original installed image/root/ceiling".into());
        }
    }
    let target_plan = plan(target, false)?;
    let peer_plan = plan(peer, true)?;
    if target["workload_plan_digest"] != target_plan
        || target["authorization"]["approved_plan_digest"] != target_plan
        || peer["workload_plan_digest"] != peer_plan
        || peer["authorization"]["approved_plan_digest"] != peer_plan
        || target["expected_epoch"] != activation["epoch"]
        || peer["expected_epoch"] != activation["epoch"]
    {
        return Err("cross-attempt independently decoded source plan/epoch differs".into());
    }
    let mut expected = prior.clone();
    let definitions = expected["execution_identities"]
        .as_array()
        .ok_or("cross-attempt original identities absent")?;
    let primary = definitions
        .iter()
        .find(|definition| {
            linux_registry::linux_identity_reference(definition)
                .ok()
                .as_ref()
                == Some(&target["execution_identity"]["identity"])
        })
        .ok_or("cross-attempt original primary identity absent")?;
    let mut secondary = primary.clone();
    secondary["identity_id"] = json!("owned-cross-attempt-identity");
    secondary["uid"] = canary["peer_account"]["uid"].clone();
    secondary["gid"] = canary["peer_account"]["gid"].clone();
    secondary["reservation_key"] = json!("owned-cross-attempt-reservation");
    let declaration = json!({"format":"memcordon.owned-readiness-exclusive-use-declaration","revision":1,"run_id":native.run_id,"cell":canary["cell"],"account":canary["peer_account"]["name"],"uid":secondary["uid"],"gid":secondary["gid"],"purpose":"exclusive original other-attempt abstract peer identity"});
    secondary["exclusive_use_policy"] = json!({"id":"owned-cross-attempt-use","digest":sha256(&serde_json::to_vec(&declaration).map_err(|error|error.to_string())?)});
    let peer_identity = json!({"identity":linux_registry::linux_identity_reference(&secondary)?,"exclusive_use_policy":secondary["exclusive_use_policy"]});
    if secondary["uid"] == primary["uid"]
        || secondary["gid"] == primary["gid"]
        || peer["execution_identity"] != peer_identity
    {
        return Err("cross-attempt original independent exclusive account aliases primary".into());
    }
    expected["execution_identities"]
        .as_array_mut()
        .ok_or("cross-attempt original identity vector absent")?
        .push(secondary);
    let grants = expected["grants"]
        .as_array_mut()
        .ok_or("cross-attempt original grants absent")?;
    let original = grants
        .iter_mut()
        .find(|grant| grant["id"] == target["authorization"]["grant_id"])
        .ok_or("cross-attempt original primary grant absent")?;
    let plans = original["approved_plans"]
        .as_array_mut()
        .ok_or("cross-attempt original approved plans absent")?;
    if !plans.contains(&json!(target_plan)) {
        plans.push(json!(target_plan));
    }
    let mut peer_grant = original.clone();
    peer_grant["id"] = json!("owned-cross-attempt-grant");
    peer_grant["execution_identity"] = peer_identity;
    peer_grant["approved_plans"] = json!([peer_plan]);
    if peer["authorization"]["grant_id"] != peer_grant["id"]
        || peer["authorization"]["grant_revision"] != peer_grant["revision"]
    {
        return Err("cross-attempt original peer grant differs".into());
    }
    grants.push(peer_grant);
    if registry != &expected {
        return Err(
            "cross-attempt broadens original authority beyond the two exact source plans".into(),
        );
    }
    let agent = product
        .components
        .iter()
        .find(|component| component.role == "sealed-agent")
        .ok_or("cross-attempt original agent absent")?;
    for (stem, receipt, policy) in [
        ("activation", &activation, registry),
        ("restoration", &restoration, &prior),
    ] {
        let policy_field = format!("{stem}_policy");
        let invocation_field = format!("{stem}_invocation");
        let exit_field = format!("{stem}_exit");
        let stderr_field = format!("{stem}_stderr");
        if decode(&policy_field)? != *policy
            || receipt["registry_digest"] != linux_registry_digest(policy, &semantic.key.target)?
        {
            return Err("cross-attempt original policy command changes unrelated authority".into());
        }
        let command = decode(&invocation_field)?;
        let protected = crate::linux_path::join(
            owner["protected_output"]
                .as_str()
                .ok_or("cross protected source directory absent")?,
            &format!("{stem}.policy.json"),
        );
        let cutoff = lease[if stem == "activation" {
            "work_deadline_unix_millis"
        } else {
            "cleanup_deadline_unix_millis"
        }]
        .as_u64()
        .filter(|value| *value > 0)
        .ok_or("cross original policy cutoff absent")?;
        let started = command["started_unix_millis"]
            .as_u64()
            .filter(|value| *value > 0 && *value < cutoff)
            .ok_or("cross policy starts outside original cutoff")?;
        if command["deadline_unix_millis"] != cutoff
            || command["budget_millis"]
                .as_u64()
                .is_none_or(|budget| budget == 0 || budget > cutoff - started || budget > 60000)
        {
            return Err("cross policy refreshes original deadline authority".into());
        }
        if command["arguments"][4] != json!(protected.as_bytes()) {
            return Err("cross policy command substitutes original protected source file".into());
        }
        policy_command(
            &command,
            &decode(&exit_field)?,
            custody.bytes(path(&invocation_field)?)?,
            custody.bytes(path(stem)?)?,
            custody.bytes(path(&stderr_field)?)?,
            custody.bytes(path(&policy_field)?)?,
            &agent.installed_sha256,
        )?;
    }
    linux_policy::validate_prepared_native_graph(
        &peer_prepared,
        &peer_binding,
        &peer_request["contract"],
        &peer_prepared["provider"],
        &activation,
        custody.hash(path("peer_prepared")?)?,
        &native.run_id,
        peer_binding["attempt_id"]
            .as_str()
            .ok_or("cross-attempt original peer attempt absent")?,
    )?;
    let listener = &canary["listener"];
    closed(
        listener,
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
    let observed = &listener["observation"];
    let peer_behavior = peer_semantic
        .fixture_behavior
        .as_ref()
        .ok_or("cross-attempt original peer behavior absent")?;
    let peer_first = custody
        .bytes(&peer_behavior.transcript)?
        .split(|byte| *byte == b'\n')
        .next()
        .ok_or("cross-attempt original peer held row absent")?;
    if wire::decode::<Value>(peer_first)? != *listener {
        return Err("cross-attempt canary listener differs from original peer transcript".into());
    }
    closed(
        observed,
        &[
            "name",
            "socket_inode",
            "network_namespace_inode",
            "baseline_client_connected",
            "baseline_server_accepted",
            "bytes",
        ],
    )?;
    let held = &canary["held_peer"];
    let local = held["namespace_pids"]
        .as_array()
        .and_then(|pids| pids.last())
        .ok_or("cross-attempt original local peer PID absent")?;
    let name = format!("memcordon-readiness-{}", hex::encode(challenge)).into_bytes();
    if listener["format"] != "memcordon.linux-readiness-transcript"
        || listener["revision"] != 1
        || listener["sequence"] != 1
        || listener["operation"] != "other-attempt-abstract-held"
        || listener["challenge"] != hex::encode(challenge)
        || listener["root_pid"] != *local
        || listener["root_birth"] != held["birth"]
        || observed["name"] != json!(name)
        || canary["name"] != observed["name"]
        || observed["network_namespace_inode"] != held["network"]["inode"]
        || observed["socket_inode"]
            .as_u64()
            .is_none_or(|inode| inode == 0)
        || observed["baseline_client_connected"] != true
        || observed["baseline_server_accepted"] != true
        || observed["bytes"] != json!(b"abstract-unix-readiness".as_slice())
    {
        return Err("cross-attempt original live namespace listener lacks real roundtrip".into());
    }
    let transcript = custody.bytes(&behavior.transcript)?;
    if !transcript.ends_with(b"\n") {
        return Err("cross-attempt target original transcript truncated".into());
    }
    let rows = transcript
        .split(|byte| *byte == b'\n')
        .filter(|row| !row.is_empty())
        .map(wire::decode::<Value>)
        .collect::<Result<Vec<_>, _>>()?;
    if rows.len() != 2 {
        return Err("cross-attempt original target positive/denial sequence differs".into());
    }
    for (ordinal, row) in rows.iter().enumerate() {
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
        if row["format"] != "memcordon.linux-readiness-transcript"
            || row["revision"] != 1
            || row["sequence"] != ordinal + 1
            || row["challenge"] != hex::encode(challenge)
            || row["root_birth"].as_u64() != native.root_birth
            || row["root_pid"]
                != *target_binding["target"]["namespace_pids"]
                    .as_array()
                    .and_then(|pids| pids.last())
                    .ok_or("cross-attempt target local PID absent")?
        {
            return Err("cross-attempt original target transcript custody differs".into());
        }
    }
    closed(&rows[1]["observation"], &["name", "native_errno", "denied"])?;
    if rows[0]["operation"] != "neighboring-private-unix"
        || rows[0]["observation"]["bytes"] != json!(b"private-positive".as_slice())
        || rows[1]["operation"] != "forbidden-abstract-denied"
        || rows[1]["observation"]["name"] != canary["name"]
        || rows[1]["observation"]["native_errno"] != 111
        || rows[1]["observation"]["denied"] != true
    {
        return Err(
            "cross-attempt original target did not deny the concurrent peer listener".into(),
        );
    }
    let probe = semantic
        .negative_probe
        .as_ref()
        .ok_or("cross-attempt original native probe projection absent")?;
    if probe.stage != "other-attempt-abstract"
        || probe.domain != "linux"
        || probe.native_code != 111
        || probe.receipt != behavior.transcript
    {
        return Err("cross-attempt original denial projection differs".into());
    }
    Ok(behavior::Facts {
        operations: ["native-authority-probe".into()].into_iter().collect(),
        counters: Default::default(),
    })
}
