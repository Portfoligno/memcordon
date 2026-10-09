//! Independent executed policy transitions, including the separate fresh
//! refusal. Native completed custody is verified by the common installed route.
use crate::*;
use serde_json::Value;

fn closed(value: &Value, fields: &[&str]) -> VerificationResult<()> {
    if value.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|field| !fields.contains(&field.as_str()))
    }) {
        return Err("running policy raw schema differs".into());
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
    let key = &semantic.key;
    if key.family != "L-ID-03"
        || !["drain-running", "revoke-running", "restart-fresh-admission"]
            .contains(&key.scenario.as_str())
        || key.evidence_class != EvidenceClass::InstalledProduct
    {
        return Err("running policy decoder outside exact executed three".into());
    }
    let mut peers = BTreeMap::new();
    for peer in &behavior.peer_artifacts {
        if peers
            .insert(peer.role.as_str(), peer.path.as_str())
            .is_some()
        {
            return Err("running policy raw peer duplicated".into());
        }
    }
    let path = |role: &str| -> VerificationResult<&str> {
        peers
            .get(role)
            .copied()
            .ok_or_else(|| format!("running policy original raw peer absent: {role}"))
    };
    let json =
        |role: &str| -> VerificationResult<Value> { wire::decode(custody.bytes(path(role)?)?) };
    let product = index
        .products
        .iter()
        .find(|product| {
            product.key.target == key.target
                && Some(product.key.channel.as_str()) == key.channel.as_deref()
        })
        .ok_or("running policy selected product absent")?;
    let agent = product
        .components
        .iter()
        .find(|component| component.role == "sealed-agent")
        .ok_or("running policy selected agent absent")?;
    let cli = product
        .components
        .iter()
        .find(|component| component.role == "public-cli")
        .ok_or("running policy selected CLI absent")?;
    if custody.hash(path("policy-agent-image")?)? != agent.installed_sha256 {
        return Err(
            "running policy native mutation agent differs from selected installed product".into(),
        );
    }
    let owner = json("policy-owner")?;
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
    let admin = owner["admin_root"]
        .as_str()
        .ok_or("running policy original administrator root absent")?;
    let privileged = owner["privileged_policy_root"]
        .as_str()
        .ok_or("running policy protected staging absent")?;
    if owner["format"] != "memcordon.linux-policy-case-owner"
        || owner["revision"] != 1
        || owner["run_id"] != native.run_id
        || owner["source_commit"] != index.source_commit
        || owner["source_tree_sha256"] != index.source_tree_sha256
        || owner["cell"] != serde_json::to_value(&product.key).map_err(|error| error.to_string())?
        || owner["lease_id"].as_str() != native.lease_id.as_deref()
        || !admin.starts_with("/var/lib/memcordon-consumer-readiness/")
        || privileged
            != format!(
                "{admin}/policy-cases-{}",
                native
                    .lease_id
                    .as_deref()
                    .ok_or("running policy native lease absent")?
            )
    {
        return Err("running policy original source/cell/staging owner differs".into());
    }
    let lifecycle: InstalledLifecycleJournal =
        wire::decode(custody.bytes(&product.lifecycle.journal)?)?;
    let administrative = lifecycle
        .events
        .iter()
        .filter(|event| {
            event.phase == "owned-before-mutation"
                && event.operation == "administrative-staging-created"
                && event.succeeded
        })
        .collect::<Vec<_>>();
    if administrative.len() != 1 {
        return Err("running policy original administrator acquisition not unique".into());
    }
    let original: Value = wire::decode(custody.bytes(&administrative[0].native_receipt)?)?;
    if original["path"] != owner["admin_root"]
        || original["device"] != owner["admin_root_device"]
        || original["inode"] != owner["admin_root_inode"]
    {
        return Err("running policy administrator native inode differs".into());
    }
    if key.scenario == "restart-fresh-admission" {
        return validate_restart(
            behavior,
            semantic,
            native,
            evidence,
            index,
            custody,
            &owner,
            &agent.installed_sha256,
        );
    }
    let activation = json("policy-activation-json")?;
    let revocation = json("policy-revocation-json")?;
    let restoration = json("policy-restoration-json")?;
    let baseline = &owner["baseline_registry"];
    let mut changed = baseline.clone();
    changed["grants"][0]["enabled"] = false.into();
    changed["active_attempt_disposition"] = if key.scenario == "drain-running" {
        "drain-existing"
    } else {
        "revoke-active"
    }
    .into();
    if linux_policy::activation_registry(&activation)? != baseline
        || linux_policy::activation_registry(&revocation)? != &changed
        || linux_policy::activation_registry(&restoration)? != baseline
    {
        return Err("running policy revocation/restoration changes unrelated authority".into());
    }
    for (stem, receipt, policy) in [
        ("activation", &activation, baseline),
        ("revocation", &revocation, &changed),
        ("restoration", &restoration, baseline),
    ] {
        let registry = json(&format!("policy-{stem}-policy.json"))?;
        if registry != *policy
            || receipt["registry_digest"] != linux_registry_digest(policy, &key.target)?
        {
            return Err("running policy actual canonical registry mutation differs".into());
        }
        let command = json(&format!("policy-{stem}-invocation.json"))?;
        closed(
            &command,
            &[
                "format",
                "revision",
                "agent_sha256",
                "program",
                "arguments",
                "cwd",
                "environment_cleared",
                "budget_millis",
                "policy_sha256",
            ],
        )?;
        let args: Vec<Vec<u8>> = serde_json::from_value(command["arguments"].clone())
            .map_err(|error| error.to_string())?;
        if command["format"] != "memcordon.linux-policy-activation-command"
            || command["revision"] != 1
            || command["agent_sha256"] != agent.installed_sha256
            || command["program"]
                != serde_json::json!(b"/usr/libexec/memcordon-sealed-agent".to_vec())
            || command["environment_cleared"] != true
            || command["budget_millis"]
                .as_u64()
                .is_none_or(|value| value == 0 || value > 60000)
            || args
                != [
                    b"package".to_vec(),
                    b"policy".to_vec(),
                    b"apply".to_vec(),
                    b"--file".to_vec(),
                    format!("{privileged}/{}/{stem}.policy.json", key.scenario).into_bytes(),
                ]
            || command["policy_sha256"]
                != custody.hash(path(&format!("policy-{stem}-policy.json"))?)?
        {
            return Err("running policy mutation command leaves original agent/staging".into());
        }
        let exit = json(&format!("policy-{stem}-exit.json"))?;
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
        if exit["format"] != "memcordon.linux-policy-activation-exit"
            || exit["revision"] != 1
            || exit["native_exit"] != 0
            || exit["success"] != true
            || exit["invocation_sha256"]
                != custody.hash(path(&format!("policy-{stem}-invocation.json"))?)?
            || exit["stdout_sha256"] != custody.hash(path(&format!("policy-{stem}-json"))?)?
            || exit["stderr_sha256"] != custody.hash(path(&format!("policy-{stem}-stderr.bin"))?)?
        {
            return Err("running policy actual mutation command capture differs".into());
        }
    }
    if activation["epoch"]["service_instance"] != revocation["epoch"]["service_instance"]
        || revocation["epoch"]["service_instance"] != restoration["epoch"]["service_instance"]
        || activation["epoch"]["revision"].as_u64() >= revocation["epoch"]["revision"].as_u64()
        || revocation["epoch"]["revision"].as_u64() >= restoration["epoch"]["revision"].as_u64()
    {
        return Err("running policy original epoch sequence differs".into());
    }
    let request: Value = wire::decode(
        custody.bytes(
            evidence
                .request
                .as_deref()
                .ok_or("running policy admitted request absent")?,
        )?,
    )?;
    if request["expected_epoch"] != activation["epoch"] {
        return Err("running policy old admission is not original activation".into());
    }
    let positive = index
        .records
        .iter()
        .find(|record| {
            record.key.target == key.target
                && record.key.channel == key.channel
                && record.key.family == "C-ADMISSION"
                && record.key.scenario == "positive"
                && record.key.evidence_class == EvidenceClass::InstalledProduct
        })
        .ok_or("running policy original baseline admission absent")?;
    let products = index
        .products
        .iter()
        .map(|product| (product.key.clone(), product))
        .collect();
    let builds = index
        .component_builds
        .iter()
        .map(|build| (build.recipe_id.clone(), build))
        .collect();
    crate::verify_record(index, positive, &products, &builds, custody)?;
    let baseline_evidence: CaseEvidence = wire::decode(
        custody.bytes(
            positive
                .evidence
                .as_deref()
                .ok_or("running policy original baseline raw evidence absent")?,
        )?,
    )?;
    let mut baseline_request: Value = wire::decode(
        custody.bytes(
            baseline_evidence
                .request
                .as_deref()
                .ok_or("running policy original baseline request absent")?,
        )?,
    )?;
    let mut admitted = request.clone();
    baseline_request
        .as_object_mut()
        .ok_or("running policy baseline request is not object")?
        .remove("expected_epoch");
    admitted
        .as_object_mut()
        .ok_or("running policy admitted request is not object")?
        .remove("expected_epoch");
    if admitted != baseline_request {
        return Err(
            "running policy original authority differs from independently verified baseline".into(),
        );
    }
    let running = json("policy-running-native-held.json")?;
    closed(
        &running,
        &[
            "format",
            "revision",
            "attempt_id",
            "target",
            "challenge",
            "fixture_row",
            "held_descendants",
            "native_descendants",
        ],
    )?;
    if running["format"] != "memcordon.linux-policy-running-native-held"
        || running["revision"] != 1
        || running["attempt_id"].as_str() != native.attempt_id.as_deref()
        || running["target"]["pid"].as_u64() != native.root_pid.map(u64::from)
        || running["target"]["birth"].as_u64() != native.root_birth
        || running["challenge"] != hex::encode(custody.bytes(&semantic.challenge)?)
    {
        return Err("running policy mutates unrelated held existing target".into());
    }
    let descendants = running["held_descendants"]
        .as_array()
        .ok_or("running policy held cohort absent")?;
    if descendants.len() != 1 {
        return Err("running policy did not retain actual original cooperation child".into());
    }
    let input: FixtureInput = wire::decode(custody.bytes(&evidence.input)?)?;
    let expected_arguments = vec![
        b"cooperation".to_vec(),
        hex::encode(custody.bytes(&semantic.challenge)?).into_bytes(),
    ];
    if !matches!(&input.target_argv,NativeArguments::UnixBytes(arguments)if arguments==&expected_arguments)
        || input.memory_bytes != Some(256 * 1024 * 1024)
        || input
            .deadline_millis
            .is_none_or(|budget| budget == 0 || budget > 30000)
    {
        return Err("running policy original admitted recipe differs".into());
    }
    let binding: Value = wire::decode(
        custody.bytes(
            evidence
                .prepared_native_receipt
                .as_deref()
                .ok_or("running policy original held namespace graph absent")?,
        )?,
    )?;
    let snapshots = running["native_descendants"]
        .as_array()
        .filter(|snapshots| snapshots.len() == 1)
        .ok_or("running policy independently held child namespace absent")?;
    let row = &running["fixture_row"];
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
    let local_root = binding["target"]["namespace_pids"]
        .as_array()
        .and_then(|pids| pids.last())
        .and_then(Value::as_u64)
        .ok_or("running policy original target local PID absent")?;
    if row["format"] != "memcordon.linux-readiness-transcript"
        || row["revision"] != 1
        || row["sequence"] != 1
        || row["challenge"] != running["challenge"]
        || row["root_pid"] != local_root
        || row["root_birth"].as_u64() != native.root_birth
        || row["operation"] != "same-attempt-cooperation-held"
    {
        return Err("running policy original cooperative barrier differs".into());
    }
    let observation = &row["observation"];
    closed(
        observation,
        &["pid", "birth", "members", "endpoint", "transcript"],
    )?;
    let endpoint: std::net::SocketAddr = observation["endpoint"]
        .as_str()
        .ok_or("running policy cooperative endpoint absent")?
        .parse()
        .map_err(|_| "running policy cooperative endpoint malformed")?;
    if endpoint.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        || endpoint.port() == 0
        || observation["members"] != serde_json::json!([])
    {
        return Err("running policy original cooperative boundary differs".into());
    }
    let child = &snapshots[0];
    closed(
        child,
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
    let mapped = child["namespace_pids"]
        .as_array()
        .filter(|pids| {
            !pids.is_empty()
                && pids.len() <= 32
                && pids.iter().all(|pid| {
                    pid.as_u64()
                        .is_some_and(|pid| pid > 0 && pid <= u64::from(u32::MAX))
                })
        })
        .ok_or("running policy original child namespace mapping malformed")?;
    if child["process_id"] != descendants[0]["pid"]
        || child["birth"] != descendants[0]["birth"]
        || mapped.first() != Some(&child["process_id"])
        || mapped.last() != Some(&observation["pid"])
        || observation["birth"] != child["birth"]
    {
        return Err("running policy cooperative row substitutes original held child".into());
    }
    for ns in ["user", "mount", "pid", "network", "ipc"] {
        if child[ns] != binding["target"][ns] {
            return Err("running policy cooperative child leaves original target namespace".into());
        }
    }
    let ready: Vec<u8> = serde_json::from_value(observation["transcript"].clone())
        .map_err(|error| error.to_string())?;
    if ready.len() > 65536 || !ready.ends_with(b"\n") || ready[..ready.len() - 1].contains(&b'\n') {
        return Err("running policy original child readiness capture malformed".into());
    }
    let ready: Value = wire::decode(&ready[..ready.len() - 1])?;
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
    closed(&ready["observation"], &["endpoint"])?;
    if ready["format"] != row["format"]
        || ready["revision"] != 1
        || ready["sequence"] != 1
        || ready["challenge"] != row["challenge"]
        || ready["root_pid"] != observation["pid"]
        || ready["root_birth"] != observation["birth"]
        || ready["operation"] != "cooperation-peer-ready"
        || ready["observation"]["endpoint"] != observation["endpoint"]
    {
        return Err("running policy original child readiness source differs".into());
    }
    let transcript = custody
        .bytes(&behavior.transcript)?
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(wire::decode::<Value>)
        .collect::<VerificationResult<Vec<_>>>()?;
    let count = if key.scenario == "drain-running" {
        2
    } else {
        1
    };
    if transcript.len() != count || transcript[0] != *row {
        return Err(
            "running policy original held row differs from captured fixture transcript".into(),
        );
    }
    if count == 2 {
        let completed = &transcript[1];
        closed(
            completed,
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
        let effect = &completed["observation"];
        closed(
            effect,
            &[
                "pid",
                "birth",
                "endpoint",
                "server_received",
                "peer_transcript",
                "native_status",
            ],
        )?;
        let peer_bytes: Vec<u8> = serde_json::from_value(effect["peer_transcript"].clone())
            .map_err(|error| error.to_string())?;
        if peer_bytes.len() > 65536
            || !peer_bytes.ends_with(b"\n")
            || peer_bytes[..peer_bytes.len() - 1].contains(&b'\n')
        {
            return Err("running policy original child completion capture malformed".into());
        }
        let peer: Value = wire::decode(&peer_bytes[..peer_bytes.len() - 1])?;
        closed(
            &peer,
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
        closed(&peer["observation"], &["endpoint", "bytes"])?;
        let challenge =
            serde_json::json!(hex::encode(custody.bytes(&semantic.challenge)?).into_bytes());
        if completed["format"] != row["format"]
            || completed["revision"] != 1
            || completed["sequence"] != 2
            || completed["challenge"] != row["challenge"]
            || completed["root_pid"] != row["root_pid"]
            || completed["root_birth"] != row["root_birth"]
            || completed["operation"] != "same-attempt-cooperation-complete"
            || effect["pid"] != observation["pid"]
            || effect["birth"] != observation["birth"]
            || effect["endpoint"] != observation["endpoint"]
            || effect["server_received"] != challenge
            || effect["native_status"] != 0
            || peer["format"] != row["format"]
            || peer["revision"] != 1
            || peer["sequence"] != 2
            || peer["challenge"] != row["challenge"]
            || peer["root_pid"] != observation["pid"]
            || peer["root_birth"] != observation["birth"]
            || peer["operation"] != "cooperation-peer-received"
            || peer["observation"]["endpoint"] != observation["endpoint"]
            || peer["observation"]["bytes"] != challenge
        {
            return Err("drain original admitted cooperative bytes/Child wait differ".into());
        }
    }
    for process in descendants {
        let original: HeldProcessIdentity =
            serde_json::from_value(process.clone()).map_err(|error| error.to_string())?;
        if original.retirement_observed
            || original.pid == 0
            || original.pid > i32::MAX as u32
            || native.root_birth.is_none_or(|birth| original.birth < birth)
            || original.parent_pid != native.root_pid
            || original.parent_birth != native.root_birth
        {
            return Err("running policy original native cohort ownership differs".into());
        }
    }
    let retired = json("policy-prepared-family-retirement.json")?;
    closed(
        &retired,
        &[
            "format",
            "revision",
            "attempt_id",
            "admission_nonce",
            "target",
            "namespace_init",
            "guardian",
            "target_retirement",
            "namespace_init_retirement",
            "guardian_retirement",
            "held_before_revocation",
            "native_family_retired",
            "held_descendants",
        ],
    )?;
    if retired["format"] != "memcordon.linux-policy-prepared-family-retirement"
        || retired["revision"] != 1
        || retired["held_before_revocation"] != true
    {
        return Err("running policy native retirement schema differs".into());
    }
    for (original, retirement) in [
        ("target", "target_retirement"),
        ("namespace_init", "namespace_init_retirement"),
        ("guardian", "guardian_retirement"),
    ] {
        let process: HeldProcessIdentity = serde_json::from_value(retired[retirement].clone())
            .map_err(|error| error.to_string())?;
        if !process.retirement_observed
            || retired[original]["pid"] != process.pid
            || retired[original]["birth"] != process.birth
        {
            return Err("running policy held family settlement differs".into());
        }
    }
    let settled: Vec<HeldProcessIdentity> =
        serde_json::from_value(retired["held_descendants"].clone())
            .map_err(|error| error.to_string())?;
    if settled.len() != descendants.len()
        || retired["native_family_retired"] != true
        || retired["attempt_id"] != running["attempt_id"]
    {
        return Err("running policy original cohort not fully settled".into());
    }
    for (before, after) in descendants.iter().zip(settled) {
        let before: HeldProcessIdentity =
            serde_json::from_value(before.clone()).map_err(|error| error.to_string())?;
        if !after.retirement_observed
            || after.pid != before.pid
            || after.birth != before.birth
            || after.parent_pid != before.parent_pid
            || after.parent_birth != before.parent_birth
        {
            return Err("running policy native cohort retirement substitutes identity".into());
        }
    }
    let mut cohort = BTreeSet::new();
    for process in descendants {
        let original: HeldProcessIdentity =
            serde_json::from_value(process.clone()).map_err(|error| error.to_string())?;
        if Some(original.pid) == native.root_pid
            || !cohort.insert((original.pid, original.birth))
            || native
                .held_processes
                .iter()
                .filter(|held| {
                    held.pid == original.pid
                        && held.birth == original.birth
                        && held.parent_pid == original.parent_pid
                        && held.parent_birth == original.parent_birth
                        && held.retirement_observed
                })
                .count()
                != 1
        {
            return Err("running policy original cohort native custody differs".into());
        }
    }
    if native.held_processes.len() != cohort.len() + 1
        || native
            .held_processes
            .iter()
            .filter(|held| {
                Some(held.pid) == native.root_pid
                    && Some(held.birth) == native.root_birth
                    && held.retirement_observed
                    && held.parent_pid.is_none()
                    && held.parent_birth.is_none()
            })
            .count()
            != 1
    {
        return Err("running policy original native cohort closure differs".into());
    }
    let fresh = json("policy-fresh-contract.json")?;
    let mut expected = request.clone();
    expected["expected_epoch"] = revocation["epoch"].clone();
    if fresh != expected {
        return Err("running policy fresh refusal substitutes original requested authority".into());
    }
    let fresh_challenge = custody.bytes(path("policy-fresh-challenge.bin")?)?;
    if fresh_challenge == custody.bytes(&semantic.challenge)? {
        return Err("running policy fresh attempt reuses old challenge".into());
    }
    let fresh_result = json("policy-fresh-result.json")?;
    let fresh_exit = json("policy-fresh-exit.json")?;
    closed(
        &fresh_exit,
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
    linux_policy::validate_linux_policy_frontend(
        &json("policy-fresh-frontend-invocation.json")?,
        &fresh_result["invocation"],
        fresh_challenge,
        65534,
        &cli.installed_sha256,
    )?;
    let status = fresh_exit["native_exit"]
        .as_i64()
        .and_then(|value| i32::try_from(value).ok())
        .ok_or("running policy fresh native status absent")?;
    let pid = fresh_exit["process_id"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .ok_or("running policy fresh native birth owner absent")?;
    let prepared: Value = wire::decode(
        custody.bytes(
            evidence
                .prepared_observation
                .as_deref()
                .ok_or("running policy original prepared family absent")?,
        )?,
    )?;
    if ["caller", "target", "namespace_init", "guardian"]
        .iter()
        .any(|role| prepared[*role]["pid"] == pid)
        || native.held_processes.iter().any(|held| held.pid == pid)
    {
        return Err("running policy fresh frontend aliases original admitted family".into());
    }
    linux_policy::validate_linux_policy_refusal_result(
        &fresh_result,
        custody.bytes(path("policy-fresh-provider-request.json")?)?,
        &fresh,
        &fresh_result["invocation"],
        &index.version,
        &key.target,
        status,
        pid,
        "disabled-grant",
    )?;
    if fresh_exit["raw_wait_status"] != status << 8
        || !fresh_exit["signal"].is_null()
        || fresh_exit["process_birth"]
            .as_u64()
            .is_none_or(|value| value == 0)
        || fresh_exit["invocation_sha256"]
            != custody.hash(path("policy-fresh-frontend-invocation.json")?)?
        || fresh_exit["stdout_sha256"] != custody.hash(path("policy-fresh-stdout.bin")?)?
        || fresh_exit["stderr_sha256"] != custody.hash(path("policy-fresh-stderr.bin")?)?
    {
        return Err("running policy fresh command capture differs".into());
    }
    let identity = serde_json::json!({"run_id":evidence.run_id,"source_commit":evidence.source_commit,"source_tree_sha256":evidence.source_tree_sha256,"version":index.version});
    let mut account = None;
    for artifact in index
        .artifacts
        .iter()
        .filter(|artifact| artifact.path.ends_with("/owned-resources-acquired.json"))
    {
        let checkpoint: Value = wire::decode(custody.bytes(&artifact.path)?)?;
        if checkpoint["identity"] != identity
            || checkpoint["cell"] != owner["cell"]
            || checkpoint["admin_root"] != owner["admin_root"]
        {
            continue;
        }
        if checkpoint["device"] != owner["admin_root_device"]
            || checkpoint["inode"] != owner["admin_root_inode"]
            || checkpoint["legacy"] != baseline["legacy"]
            || account.replace(checkpoint["account"].clone()).is_some()
        {
            return Err("running policy original acquired account ambiguous/substituted".into());
        }
    }
    let account = account.ok_or("running policy original exclusive account checkpoint absent")?;
    if baseline["execution_identities"]
        .as_array()
        .is_none_or(|identities| {
            identities.len() != 1
                || identities[0]["enabled"] != true
                || identities[0]["uid"] != account["uid"]
                || identities[0]["gid"] != account["gid"]
        })
    {
        return Err("running policy acquired account differs from selected identity".into());
    }
    let census = json("policy-fresh-native-census.json")?;
    let attempt = path("policy-fresh-provider-request.json")?
        .rsplit('/')
        .next()
        .and_then(|name| name.strip_prefix("policy-fresh-"))
        .and_then(|name| name.strip_suffix(".provider-request.bin"))
        .ok_or("running policy original fresh refusal attempt basename absent")?;
    if Some(attempt) == native.attempt_id.as_deref() {
        return Err("running policy fresh refusal reuses original admitted attempt".into());
    }
    validate_linux_refusal_census(
        &census,
        &identity,
        &owner["cell"],
        native
            .lease_id
            .as_deref()
            .ok_or("running policy original lease absent")?,
        &key.scenario,
        &account,
        &owner["provider"],
        custody.hash(path("policy-fresh-provider-request.json")?)?,
        custody.hash(path("policy-fresh-result.json")?)?,
        attempt,
    )?;
    if key.scenario == "drain-running" {
        let after = json("policy-running-after-revocation.json")?;
        closed(
            &after,
            &["format", "revision", "attempt_id", "target", "descendants"],
        )?;
        let target: HeldProcessIdentity =
            serde_json::from_value(after["target"].clone()).map_err(|error| error.to_string())?;
        if after["format"] != "memcordon.linux-policy-running-after-revocation"
            || after["revision"] != 1
            || after["attempt_id"] != running["attempt_id"]
            || target.retirement_observed
            || Some(target.pid) != native.root_pid
            || Some(target.birth) != native.root_birth
            || after["descendants"] != running["held_descendants"]
            || native.origin != OutcomeOrigin::Target
            || native.target_status != Some(0)
            || revocation["revoked_admissions"] != serde_json::json!([])
        {
            return Err("drain policy did not preserve original admitted live cohort".into());
        }
    } else {
        let result: Value = wire::decode(
            custody.bytes(
                evidence
                    .raw_result
                    .as_deref()
                    .ok_or("running revoke actual original result absent")?,
            )?,
        )?;
        let admission = &result["runtime"]["outcome"]["admission"];
        if native.origin != OutcomeOrigin::ProviderFailure
            || result["runtime"]["outcome"]["execution"]["outcome_origin"] != "revoked"
            || admission["admission_nonce"] != retired["admission_nonce"]
            || !revocation["revoked_admissions"]
                .as_array()
                .is_some_and(|nonces| nonces.contains(&admission["admission_nonce"]))
        {
            return Err("revoke policy did not revoke exact original live admission".into());
        }
    }
    Ok(behavior::Facts {
        operations: BTreeSet::from([format!("policy-{}", key.scenario)]),
        counters: Default::default(),
    })
}

#[expect(
    clippy::too_many_arguments,
    reason = "Compare independent running policy, native behavior, owner and retained custody observations"
)]
fn validate_restart(
    behavior: &FixtureBehavior,
    semantic: &SemanticObservation,
    native: &NativeObservation,
    evidence: &CaseEvidence,
    index: &EvidenceIndex,
    custody: &custody::Custody,
    owner: &Value,
    agent: &str,
) -> VerificationResult<behavior::Facts> {
    let peers = behavior
        .peer_artifacts
        .iter()
        .map(|peer| (peer.role.as_str(), peer.path.as_str()))
        .collect::<BTreeMap<_, _>>();
    let path = |role: &str| -> VerificationResult<&str> {
        peers
            .get(role)
            .copied()
            .ok_or_else(|| format!("restart original native peer absent: {role}"))
    };
    let json =
        |role: &str| -> VerificationResult<Value> { wire::decode(custody.bytes(path(role)?)?) };
    let key = &semantic.key;
    if native.origin != OutcomeOrigin::Target || native.target_status != Some(0) {
        return Err("restart fresh admission did not complete naturally".into());
    }
    let mut http = None;
    for line in custody
        .bytes(&behavior.transcript)?
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        let row: Value = wire::decode(line)?;
        if row["operation"] == "http-round-trip"
            && http.replace(row["observation"].clone()).is_some()
        {
            return Err("restart fresh HTTP effect duplicated".into());
        }
    }
    let http = http.ok_or("restart fresh native target omitted actual HTTP request/response")?;
    closed(&http, &["endpoint", "peer", "request", "response"])?;
    let endpoint: std::net::SocketAddr = http["endpoint"]
        .as_str()
        .ok_or("restart HTTP endpoint absent")?
        .parse()
        .map_err(|_| "restart HTTP endpoint invalid")?;
    let peer: std::net::SocketAddr = http["peer"]
        .as_str()
        .ok_or("restart HTTP peer absent")?
        .parse()
        .map_err(|_| "restart HTTP peer invalid")?;
    if endpoint.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        || peer.ip() != endpoint.ip()
        || endpoint.port() == 0
        || peer.port() == 0
        || http["request"]
            != serde_json::json!(
                b"GET /readiness HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".to_vec()
            )
        || http["response"]
            != serde_json::json!(
                b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nreadiness"
                    .to_vec()
            )
    {
        return Err(
            "restart fresh native HTTP effects differ from known actual byte vector".into(),
        );
    }
    let before = json("policy-before.service-native.json")?;
    let after = json("policy-after.service-native.json")?;
    for (stage, service) in [("before", &before), ("after", &after)] {
        closed(
            service,
            &[
                "format",
                "revision",
                "stage",
                "unit",
                "process_id",
                "birth",
                "image",
                "image_sha256",
                "held_live",
                "native_unit_exit",
            ],
        )?;
        if service["format"] != "memcordon.linux-policy-control-service-native"
            || service["revision"] != 1
            || service["stage"] != stage
            || service["unit"] != "memcordon-sealed-agent.service"
            || service["image"] != "/usr/libexec/memcordon-sealed-agent"
            || service["image_sha256"] != agent
            || service["held_live"] != true
            || service["native_unit_exit"] != 0
            || service["process_id"]
                .as_u64()
                .is_none_or(|pid| pid == 0 || pid > i32::MAX as u64)
            || service["birth"].as_u64().is_none_or(|birth| birth == 0)
        {
            return Err("restart old/current unit native identity differs".into());
        }
    }
    let generation = json("policy-control-generation-settlement.json")?;
    closed(&generation, &["format", "revision", "old", "current"])?;
    let old: HeldProcessIdentity =
        serde_json::from_value(generation["old"].clone()).map_err(|error| error.to_string())?;
    let current: HeldProcessIdentity =
        serde_json::from_value(generation["current"].clone()).map_err(|error| error.to_string())?;
    if generation["format"] != "memcordon.linux-policy-control-generation-settlement"
        || generation["revision"] != 1
        || !old.retirement_observed
        || current.retirement_observed
        || before["process_id"] != old.pid
        || before["birth"] != old.birth
        || after["process_id"] != current.pid
        || after["birth"] != current.birth
        || (old.pid, old.birth) == (current.pid, current.birth)
    {
        return Err(
            "restart did not retire original unit and hold a fresh native generation".into(),
        );
    }
    let tool = custody.hash(path("policy-control-tool-image")?)?;
    let mut command_creations = BTreeSet::new();
    for stem in ["before-show", "restart", "after-show"] {
        let command = json(&format!("policy-{stem}-command.json"))?;
        let exit = json(&format!("policy-{stem}-command-exit.json"))?;
        closed(
            &command,
            &[
                "format",
                "revision",
                "program",
                "arguments",
                "cwd",
                "environment",
                "program_sha256",
                "program_device",
                "program_inode",
                "budget_millis",
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
        closed(&exit["creation"], &["pid", "birth", "image"])?;
        let args = if stem == "restart" {
            vec![
                b"restart".to_vec(),
                b"memcordon-sealed-agent.service".to_vec(),
            ]
        } else {
            vec![
                b"show".to_vec(),
                b"--property=MainPID".to_vec(),
                b"--value".to_vec(),
                b"memcordon-sealed-agent.service".to_vec(),
            ]
        };
        let retirement: HeldProcessIdentity = serde_json::from_value(exit["retirement"].clone())
            .map_err(|error| error.to_string())?;
        if command["format"] != "memcordon.linux-policy-control-command"
            || command["revision"] != 1
            || command["program"] != serde_json::json!(b"/usr/bin/systemctl".to_vec())
            || command["arguments"] != serde_json::json!(args)
            || command["environment"] != serde_json::json!([])
            || command["program_sha256"] != tool
            || ["program_device", "program_inode"]
                .iter()
                .any(|field| command[*field].as_u64().is_none_or(|value| value == 0))
            || command["budget_millis"]
                .as_u64()
                .is_none_or(|value| value == 0 || value > 60000)
            || exit["format"] != "memcordon.linux-policy-control-command-exit"
            || exit["revision"] != 1
            || exit["native_exit"] != 0
            || exit["raw_wait_status"] != 0
            || !exit["signal"].is_null()
            || !retirement.retirement_observed
            || exit["creation"]["pid"] != retirement.pid
            || exit["creation"]["birth"] != retirement.birth
            || retirement.pid == 0
            || retirement.birth == 0
            || !command_creations.insert((retirement.pid, retirement.birth))
            || exit["invocation_sha256"]
                != custody.hash(path(&format!("policy-{stem}-command.json"))?)?
            || exit["stdout_sha256"]
                != custody.hash(path(&format!("policy-{stem}-command.stdout.bin"))?)?
            || exit["stderr_sha256"]
                != custody.hash(path(&format!("policy-{stem}-command.stderr.bin"))?)?
        {
            return Err("restart native systemctl command/wait/capture differs".into());
        }
        let cwd: Vec<u8> =
            serde_json::from_value(command["cwd"].clone()).map_err(|error| error.to_string())?;
        if !cwd.starts_with(b"/") || cwd.contains(&0) {
            return Err("restart native command cwd malformed".into());
        }
        {
            let image = &exit["creation"]["image"];
            closed(image, &["device", "inode", "length", "sha256"])?;
            if image["device"] != command["program_device"]
                || image["inode"] != command["program_inode"]
                || image["sha256"] != tool
                || image["length"].as_u64().is_none_or(|length| length == 0)
            {
                return Err("restart native executed command image differs".into());
            }
        }
        if stem != "restart" {
            let selected = if stem == "before-show" {
                old.pid
            } else {
                current.pid
            };
            if custody.bytes(path(&format!("policy-{stem}-command.stdout.bin"))?)?
                != format!("{selected}\n").as_bytes()
            {
                return Err(
                    "restart native unit readback differs from held original process".into(),
                );
            }
        }
    }
    let activation = json("policy-activation-json")?;
    let restoration = json("policy-restoration-json")?;
    let baseline = &owner["baseline_registry"];
    if linux_policy::activation_registry(&activation)? != baseline
        || linux_policy::activation_registry(&restoration)? != baseline
        || activation["epoch"]["service_instance"] == owner["baseline_epoch"]["service_instance"]
        || activation["epoch"]["service_instance"] != restoration["epoch"]["service_instance"]
        || activation["epoch"]["revision"].as_u64() >= restoration["epoch"]["revision"].as_u64()
    {
        return Err(
            "restart admission reuses old service epoch or changes original registry".into(),
        );
    }
    for stem in ["activation", "restoration"] {
        let receipt = if stem == "activation" {
            &activation
        } else {
            &restoration
        };
        if receipt["registry_digest"] != linux_registry_digest(baseline, &key.target)?
            || json(&format!("policy-{stem}-policy.json"))? != *baseline
        {
            return Err("restart original native activated policy digest differs".into());
        }
        let command = json(&format!("policy-{stem}-invocation.json"))?;
        let exit = json(&format!("policy-{stem}-exit.json"))?;
        closed(
            &command,
            &[
                "format",
                "revision",
                "agent_sha256",
                "program",
                "arguments",
                "cwd",
                "environment_cleared",
                "budget_millis",
                "policy_sha256",
            ],
        )?;
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
        let args: Vec<Vec<u8>> = serde_json::from_value(command["arguments"].clone())
            .map_err(|error| error.to_string())?;
        let privileged = owner["privileged_policy_root"]
            .as_str()
            .ok_or("restart original policy staging absent")?;
        if command["format"] != "memcordon.linux-policy-activation-command"
            || command["revision"] != 1
            || command["agent_sha256"] != agent
            || command["program"]
                != serde_json::json!(b"/usr/libexec/memcordon-sealed-agent".to_vec())
            || command["environment_cleared"] != true
            || command["budget_millis"]
                .as_u64()
                .is_none_or(|value| value == 0 || value > 60000)
            || command["policy_sha256"]
                != custody.hash(path(&format!("policy-{stem}-policy.json"))?)?
            || args
                != [
                    b"package".to_vec(),
                    b"policy".to_vec(),
                    b"apply".to_vec(),
                    b"--file".to_vec(),
                    format!("{privileged}/restart-fresh-admission/{stem}.policy.json").into_bytes(),
                ]
            || exit["format"] != "memcordon.linux-policy-activation-exit"
            || exit["revision"] != 1
            || exit["native_exit"] != 0
            || exit["success"] != true
            || exit["invocation_sha256"]
                != custody.hash(path(&format!("policy-{stem}-invocation.json"))?)?
            || exit["stdout_sha256"] != custody.hash(path(&format!("policy-{stem}-json"))?)?
            || exit["stderr_sha256"] != custody.hash(path(&format!("policy-{stem}-stderr.bin"))?)?
        {
            return Err("restart original policy command/captures differ".into());
        }
    }
    let request: Value = wire::decode(
        custody.bytes(
            evidence
                .request
                .as_deref()
                .ok_or("restart original fresh contract absent")?,
        )?,
    )?;
    if request["expected_epoch"] != activation["epoch"] {
        return Err("restart new admission uses stale original service instance".into());
    }
    let positive = index
        .records
        .iter()
        .find(|record| {
            record.key.target == key.target
                && record.key.channel == key.channel
                && record.key.family == "C-ADMISSION"
                && record.key.scenario == "positive"
                && record.key.evidence_class == EvidenceClass::InstalledProduct
        })
        .ok_or("restart independently acquired baseline admission absent")?;
    let products = index
        .products
        .iter()
        .map(|product| (product.key.clone(), product))
        .collect();
    let builds = index
        .component_builds
        .iter()
        .map(|build| (build.recipe_id.clone(), build))
        .collect();
    crate::verify_record(index, positive, &products, &builds, custody)?;
    let baseline_evidence: CaseEvidence = wire::decode(
        custody.bytes(
            positive
                .evidence
                .as_deref()
                .ok_or("restart baseline evidence absent")?,
        )?,
    )?;
    let mut baseline_request: Value = wire::decode(
        custody.bytes(
            baseline_evidence
                .request
                .as_deref()
                .ok_or("restart baseline contract absent")?,
        )?,
    )?;
    let mut fresh_request = request.clone();
    baseline_request
        .as_object_mut()
        .ok_or("restart baseline contract malformed")?
        .remove("expected_epoch");
    fresh_request
        .as_object_mut()
        .ok_or("restart fresh contract malformed")?
        .remove("expected_epoch");
    if fresh_request != baseline_request {
        return Err(
            "restart replaces original acquired authority while changing service generation".into(),
        );
    }
    let baseline_native: NativeObservation =
        wire::decode(custody.bytes(&baseline_evidence.native_observation)?)?;
    let baseline_prepared: Value = wire::decode(
        custody.bytes(
            baseline_evidence
                .prepared_observation
                .as_deref()
                .ok_or("restart original baseline prepared family absent")?,
        )?,
    )?;
    let fresh_prepared: Value = wire::decode(
        custody.bytes(
            evidence
                .prepared_observation
                .as_deref()
                .ok_or("restart original fresh prepared family absent")?,
        )?,
    )?;
    if native.attempt_id == baseline_native.attempt_id {
        return Err("restart reuses original baseline attempt".into());
    }
    let current_birth = after["birth"]
        .as_u64()
        .ok_or("restart current native service birth absent")?;
    let mut family = BTreeSet::new();
    for role in ["caller", "target", "namespace_init", "guardian"] {
        let fresh = &fresh_prepared[role];
        let pid = fresh["pid"]
            .as_u64()
            .filter(|pid| *pid > 0)
            .ok_or("restart fresh family PID absent")?;
        let birth = fresh["birth"]
            .as_u64()
            .filter(|birth| *birth >= current_birth)
            .ok_or("restart fresh family predates current native control generation")?;
        if !family.insert((pid, birth))
            || ["caller", "target", "namespace_init", "guardian"]
                .iter()
                .any(|old| {
                    baseline_prepared[*old]["pid"] == pid
                        && baseline_prepared[*old]["birth"] == birth
                })
        {
            return Err("restart fresh family aliases original admitted family".into());
        }
    }
    let retirement = json("policy-fresh-family-retirement.json")?;
    closed(
        &retirement,
        &[
            "format",
            "revision",
            "prepared",
            "native_family_retired",
            "target_retirement",
            "namespace_init_retirement",
            "guardian_retirement",
            "old_control_retired",
            "new_control_live",
        ],
    )?;
    let prepared: Value = wire::decode(
        custody.bytes(
            evidence
                .prepared_observation
                .as_deref()
                .ok_or("restart actual prepared observation absent")?,
        )?,
    )?;
    if retirement["format"] != "memcordon.linux-policy-restarted-family-retirement"
        || retirement["revision"] != 1
        || retirement["prepared"] != prepared
        || retirement["native_family_retired"] != true
        || retirement["old_control_retired"] != true
        || retirement["new_control_live"] != true
    {
        return Err("restart fresh family settlement differs".into());
    }
    for (field, process) in [
        ("target_retirement", "target"),
        ("namespace_init_retirement", "namespace_init"),
        ("guardian_retirement", "guardian"),
    ] {
        let retired: HeldProcessIdentity =
            serde_json::from_value(retirement[field].clone()).map_err(|error| error.to_string())?;
        if !retired.retirement_observed
            || prepared[process]["pid"] != retired.pid
            || prepared[process]["birth"] != retired.birth
        {
            return Err("restart family retirement adopts another process birth".into());
        }
    }
    Ok(behavior::Facts {
        operations: BTreeSet::from(["policy-restart-fresh-admission".into()]),
        counters: Default::default(),
    })
}
