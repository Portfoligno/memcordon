use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// A public frontend ran and the provider refused before releasing a target.
/// Preparation and final-release gates retain the actual native family and
/// its independently acquired retirement through the scoped gate member.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxPolicyRefusalEvidence {
    pub format: String,
    pub revision: u32,
    pub key: crate::CaseKey,
    pub run_id: String,
    pub source_commit: String,
    pub source_tree_sha256: String,
    pub lease_id: String,
    pub baseline_registry: String,
    pub baseline_contract: String,
    pub baseline_activation: String,
    pub earlier_activations: Vec<String>,
    #[serde(default)]
    pub discovery: Option<LinuxPolicyDiscoveryEvidence>,
    #[serde(default)]
    pub gate: Option<LinuxPolicyGateEvidence>,
    pub activation: String,
    pub activation_policy: String,
    pub activation_invocation: String,
    pub activation_exit: String,
    pub activation_stderr: String,
    pub restoration: String,
    pub restoration_policy: String,
    pub restoration_invocation: String,
    pub restoration_exit: String,
    pub restoration_stderr: String,
    pub requested_contract: String,
    pub provider_request: String,
    pub raw_result: String,
    pub invocation: String,
    pub frontend_invocation: String,
    pub frontend_exit: String,
    pub stdout: String,
    pub stderr: String,
    pub challenge: String,
    pub native_census: String,
    pub owner: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxPolicyDiscoveryEvidence {
    pub contract: String,
    pub invocation: String,
    pub stdout: String,
    pub stderr: String,
    pub exit: String,
    pub revocation: String,
    pub revocation_policy: String,
    pub revocation_invocation: String,
    pub revocation_exit: String,
    pub revocation_stderr: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxPolicyGateEvidence {
    pub prepared: String,
    pub prepared_native: String,
    pub retirement: String,
    pub acknowledgment: String,
    pub revocation: String,
    pub revocation_policy: String,
    pub revocation_invocation: String,
    pub revocation_exit: String,
    pub revocation_stderr: String,
    pub release: Option<String>,
    pub release_ack: Option<String>,
}

impl LinuxPolicyRefusalEvidence {
    pub(crate) fn artifact_paths(&self) -> Vec<&str> {
        let mut paths = vec![
            self.baseline_registry.as_str(),
            self.baseline_contract.as_str(),
            self.baseline_activation.as_str(),
            self.activation.as_str(),
            self.activation_policy.as_str(),
            self.activation_invocation.as_str(),
            self.activation_exit.as_str(),
            self.activation_stderr.as_str(),
            self.restoration.as_str(),
            self.restoration_policy.as_str(),
            self.restoration_invocation.as_str(),
            self.restoration_exit.as_str(),
            self.restoration_stderr.as_str(),
            self.requested_contract.as_str(),
            self.provider_request.as_str(),
            self.raw_result.as_str(),
            self.invocation.as_str(),
            self.frontend_invocation.as_str(),
            self.frontend_exit.as_str(),
            self.stdout.as_str(),
            self.stderr.as_str(),
            self.challenge.as_str(),
            self.native_census.as_str(),
            self.owner.as_str(),
        ];
        paths.extend(self.earlier_activations.iter().map(String::as_str));
        if let Some(d) = &self.discovery {
            paths.extend([
                d.contract.as_str(),
                d.invocation.as_str(),
                d.stdout.as_str(),
                d.stderr.as_str(),
                d.exit.as_str(),
                d.revocation.as_str(),
                d.revocation_policy.as_str(),
                d.revocation_invocation.as_str(),
                d.revocation_exit.as_str(),
                d.revocation_stderr.as_str(),
            ]);
        }
        if let Some(g) = &self.gate {
            paths.extend([
                g.prepared.as_str(),
                g.prepared_native.as_str(),
                g.retirement.as_str(),
                g.acknowledgment.as_str(),
                g.revocation.as_str(),
                g.revocation_policy.as_str(),
                g.revocation_invocation.as_str(),
                g.revocation_exit.as_str(),
                g.revocation_stderr.as_str(),
            ]);
            paths.extend(
                g.release
                    .iter()
                    .chain(g.release_ack.iter())
                    .map(String::as_str),
            );
        }
        paths
    }
}

fn native_epoch(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or("native policy epoch is not an object")?;
    if object.len() != 2
        || !object.contains_key("service_instance")
        || !object.contains_key("revision")
        || value["revision"]
            .as_u64()
            .filter(|revision| *revision > 0)
            .is_none()
    {
        return Err("native policy epoch fields/revision differ".into());
    }
    let nonce = value["service_instance"]
        .as_array()
        .ok_or("native service instance is not a byte array")?;
    if nonce.len() != 16
        || nonce
            .iter()
            .any(|byte| byte.as_u64().filter(|byte| *byte <= 255).is_none())
    {
        return Err("native service instance differs from the sixteen-byte format".into());
    }
    Ok(())
}

/// Discovery describes the old grant; the later native provider must still
/// refuse preparation after the exact local revocation.
pub fn validate_linux_policy_discovery(
    command: &Value,
    exit: &Value,
    stdout: &[u8],
    stderr: &[u8],
    contract: &Value,
    baseline: &Value,
    activation: &Value,
    revoked: &Value,
    revocation: &Value,
    restoration: &Value,
    cli_sha256: &str,
    provider: &Value,
) -> Result<(), String> {
    closed(
        command,
        &[
            "format",
            "revision",
            "program",
            "arguments",
            "caller_uid",
            "caller_gid",
            "environment_cleared",
            "cli_sha256",
        ],
    )?;
    closed(exit, &["native_exit", "stdout_sha256", "stderr_sha256"])?;
    let arguments: Vec<Vec<u8>> =
        serde_json::from_value(command["arguments"].clone()).map_err(|error| error.to_string())?;
    let fixed = [
        "--reuid",
        "65534",
        "--regid",
        "65534",
        "--clear-groups",
        "--",
        "/usr/libexec/memcordon",
        "doctor",
        "--json",
        "--capability-format",
        "capabilities-v2",
        "--require",
        "sealed",
        "--workload-contract",
    ];
    if command["format"] != "memcordon.linux-policy-discovery-invocation"
        || command["revision"] != 1
        || command["program"] != serde_json::json!(b"/usr/bin/setpriv".to_vec())
        || command["caller_uid"] != 65534
        || command["caller_gid"] != 65534
        || command["environment_cleared"] != true
        || command["cli_sha256"] != cli_sha256
        || arguments.len() != fixed.len() + 1
        || arguments[..fixed.len()]
            .iter()
            .zip(fixed)
            .any(|(actual, expected)| actual != expected.as_bytes())
        || exit["native_exit"] != 0
        || exit["stdout_sha256"] != crate::sha256(stdout)
        || exit["stderr_sha256"] != crate::sha256(stderr)
    {
        return Err("actual pre-revocation discovery command/capture differs".into());
    }
    let capabilities = crate::wire::json(stdout)?;
    closed(
        &capabilities,
        &[
            "format",
            "revision",
            "provider_contract",
            "launch_wire",
            "provider",
            "boot_identity",
            "profile",
            "request_versions",
            "carrier_versions",
            "supported",
            "installed_enabled",
            "exclusive_identity_eligible",
            "image_support",
            "plan",
            "authorizes_launch",
        ],
    )?;
    let plan = &capabilities["plan"];
    closed(
        plan,
        &[
            "format",
            "revision",
            "provider_contract",
            "launch_wire",
            "provider",
            "request",
            "request_sha256",
            "available_for_preparation",
            "conflict",
            "prerequisite_error",
            "pending",
            "authorizes_launch",
        ],
    )?;
    let pending = serde_json::json!([
        "authenticate-live-caller",
        "reserve-exclusive-account",
        "pin-image-and-loader-closure",
        "materialize-readonly-root",
        "observe-native-namespaces",
        "check-target-credentials-and-filter",
        "recheck-local-epoch-at-release",
        "observe-exec-event",
        "observe-live-revocation",
        "drain-and-retire-aggregate",
        "export-selected-files",
        "retire-root-and-account"
    ]);
    if capabilities["format"] != "memcordon.capabilities"
        || capabilities["revision"] != 2
        || capabilities["provider_contract"] != 4
        || capabilities["launch_wire"] != 4
        || capabilities["provider"] != *provider
        || capabilities["boot_identity"]
            .as_str()
            .is_none_or(str::is_empty)
        || capabilities["profile"] != contract["authorized_profile"]
        || capabilities["request_versions"] != serde_json::json!([3])
        || capabilities["carrier_versions"] != serde_json::json!([2])
        || [
            "supported",
            "installed_enabled",
            "exclusive_identity_eligible",
            "image_support",
        ]
        .iter()
        .any(|field| capabilities[*field] != true)
        || capabilities["authorizes_launch"] != false
        || plan["format"] != "memcordon.plan"
        || plan["revision"] != 2
        || plan["provider_contract"] != 4
        || plan["launch_wire"] != 4
        || plan["provider"] != *provider
        || plan["request"] != *contract
        || plan["request_sha256"] != crate::wire::v3_request_digest(contract)?
        || plan["available_for_preparation"] != true
        || !plan["conflict"].is_null()
        || !plan["prerequisite_error"].is_null()
        || plan["pending"] != pending
        || plan["authorizes_launch"] != false
    {
        return Err(
            "actual old discovery does not retain exact available advisory request/provider".into(),
        );
    }
    let mut expected = baseline.clone();
    expected["grants"][0]["enabled"] = false.into();
    if *revoked != expected
        || activation_registry(revocation)? != revoked
        || activation_registry(activation)? != baseline
        || activation_registry(restoration)? != baseline
        || contract["expected_epoch"] != activation["epoch"]
    {
        return Err("discovery revocation changes unrelated authority or request".into());
    }
    let epochs = [
        &activation["epoch"],
        &revocation["epoch"],
        &restoration["epoch"],
    ];
    if epochs.windows(2).any(|pair| {
        pair[0]["service_instance"] != pair[1]["service_instance"]
            || pair[0]["revision"].as_u64() >= pair[1]["revision"].as_u64()
    }) {
        return Err(
            "discovery/revocation/restoration does not follow actual native activation sequence"
                .into(),
        );
    }
    Ok(())
}

fn closed(value: &Value, fields: &[&str]) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or("policy observation is not an object")?;
    if object.len() != fields.len() || fields.iter().any(|field| !object.contains_key(*field)) {
        return Err("policy observation has unknown/missing fields".into());
    }
    Ok(())
}

pub(crate) fn validate_prepared_native_graph(
    prepared: &Value,
    native: &Value,
    requested: &Value,
    provider: &Value,
    activation: &Value,
    prepared_sha: &str,
    run_id: &str,
    attempt: &str,
) -> Result<(), String> {
    closed(
        prepared,
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
    let admission = &prepared["admission"];
    closed(
        admission,
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
    let nonce = admission["admission_nonce"]
        .as_array()
        .ok_or("prepared admission nonce absent")?;
    if prepared["format"] != "memcordon.mixed-prepared-observation"
        || prepared["revision"] != 2
        || prepared["authorizes_launch"] != false
        || prepared["provider"] != *provider
        || admission["format"] != "memcordon.private-admission-metadata"
        || admission["revision"] != 2
        || admission["attempt_id"] != attempt
        || admission["request"] != *requested
        || admission["caller_uid"] != 65534
        || admission["request_sha256"] != crate::wire::v3_request_digest(requested)?
        || admission["epoch"] != activation["epoch"]
        || admission["registry_digest"] != activation["registry_digest"]
        || admission["profile_id"] != requested["authorized_profile"]
        || nonce.len() != 16
        || nonce
            .iter()
            .any(|byte| byte.as_u64().is_none_or(|byte| byte > 255))
        || nonce.iter().all(|byte| byte == 0)
    {
        return Err(
            "actual held policy preparation crosses admitted request/provider/epoch".into(),
        );
    }
    crate::digest(
        admission["invocation_sha256"]
            .as_str()
            .ok_or("prepared invocation commitment absent")?,
    )?;
    closed(
        native,
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
    if native["format"] != "memcordon.linux-prepared-native-observation"
        || native["revision"] != 1
        || native["run_id"] != run_id
        || native["attempt_id"] != attempt
        || native["prepared_sha256"] != prepared_sha
        || native["held_before_authorization"] != true
        || native["root_device"] != prepared["root_device"]
        || native["root_inode"] != prepared["root_inode"]
        || ["root_device", "root_inode"]
            .iter()
            .any(|field| prepared[*field].as_u64().is_none_or(|value| value == 0))
        || ["pid", "birth"].iter().any(|field| {
            native["observer"][*field]
                .as_u64()
                .is_none_or(|value| value == 0)
        })
        || native["observer"]["pid"]
            .as_u64()
            .is_none_or(|value| value > i32::MAX as u64)
    {
        return Err("independently acquired preparation source/root/observer differs".into());
    }
    let mut identities = std::collections::BTreeSet::new();
    for role in ["target", "namespace_init", "guardian", "caller"] {
        let identity = &prepared[role];
        closed(identity, &["pid", "birth"])?;
        let pid = identity["pid"]
            .as_u64()
            .filter(|pid| *pid > 0 && *pid <= i32::MAX as u64)
            .ok_or("prepared process PID malformed")?;
        let birth = identity["birth"]
            .as_u64()
            .filter(|birth| *birth > 0)
            .ok_or("prepared process birth malformed")?;
        if !identities.insert((pid, birth)) || native["observer"] == *identity {
            return Err("prepared process/observer identity aliased".into());
        }
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
        if snapshot["process_id"] != pid || snapshot["birth"] != birth {
            return Err("prepared independent PIDFD snapshot differs".into());
        }
        let pids = snapshot["namespace_pids"]
            .as_array()
            .ok_or("prepared native PID tuple absent")?;
        if pids.is_empty()
            || pids.len() > 32
            || pids[0] != pid
            || pids.iter().any(|pid| {
                pid.as_u64()
                    .is_none_or(|pid| pid == 0 || pid > i32::MAX as u64)
            })
            || (role == "namespace_init" && pids.last() != Some(&Value::from(1)))
        {
            return Err("prepared native PID namespace tuple differs".into());
        }
        for (raw, field) in [
            ("user", "user_namespace"),
            ("mount", "mount_namespace"),
            ("pid", "pid_namespace"),
            ("network", "network_namespace"),
            ("ipc", "ipc_namespace"),
        ] {
            closed(&snapshot[raw], &["device", "inode"])?;
            if snapshot[raw]["device"]
                .as_u64()
                .is_none_or(|device| device == 0)
                || snapshot[raw]["inode"]
                    .as_u64()
                    .is_none_or(|inode| inode == 0)
                || (["target", "namespace_init"].contains(&role)
                    && snapshot[raw] != prepared[field])
            {
                return Err("prepared held namespace custody differs".into());
            }
        }
    }
    if native["caller"]["user"] != prepared["user_namespace"]
        || ["mount", "pid", "network", "ipc"]
            .iter()
            .any(|field| native["caller"][*field] == native["target"][*field])
    {
        return Err("prepared target does not retain the frozen fresh namespace ceiling".into());
    }
    Ok(())
}

pub fn validate_linux_policy_gate(
    scenario: &str,
    prepared: &Value,
    native: &Value,
    retired: &Value,
    ack: &Value,
    requested: &Value,
    provider: &Value,
    baseline: &Value,
    revoked: &Value,
    activation: &Value,
    revocation: &Value,
    restoration: &Value,
    prepared_sha: &str,
    run_id: &str,
    attempt: &str,
    release: Option<&Value>,
    release_ack: Option<&Value>,
) -> Result<(), String> {
    if !["revoke-preparation", "revoke-release"].contains(&scenario) {
        return Err("unfrozen policy native gate".into());
    }
    validate_prepared_native_graph(
        prepared,
        native,
        requested,
        provider,
        activation,
        prepared_sha,
        run_id,
        attempt,
    )?;
    let admission = &prepared["admission"];
    let mut expected = baseline.clone();
    expected["grants"][0]["enabled"] = false.into();
    expected["active_attempt_disposition"] = "revoke-active".into();
    if *revoked != expected
        || activation_registry(revocation)? != revoked
        || activation_registry(activation)? != baseline
        || activation_registry(restoration)? != baseline
    {
        return Err("policy gate revocation or restoration changed unrelated data".into());
    }
    for epochs in [
        &activation["epoch"],
        &revocation["epoch"],
        &restoration["epoch"],
    ]
    .windows(2)
    {
        if epochs[0]["service_instance"] != epochs[1]["service_instance"]
            || epochs[0]["revision"].as_u64() >= epochs[1]["revision"].as_u64()
        {
            return Err("policy gate activation order differs".into());
        }
    }
    closed(
        ack,
        &[
            "format",
            "revision",
            "after_revocation",
            "acknowledgment_published",
            "error",
        ],
    )?;
    if ack["format"] != "memcordon.linux-policy-observer-ack-operation"
        || ack["revision"] != 1
        || ack["after_revocation"] != true
        || ack["acknowledgment_published"] != true
        || !ack["error"].is_null()
    {
        return Err(
            "policy gate did not release its actual observer barrier after revocation".into(),
        );
    }
    closed(
        retired,
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
        || retired["attempt_id"] != attempt
        || retired["admission_nonce"] != admission["admission_nonce"]
        || retired["held_before_revocation"] != true
        || retired["native_family_retired"] != true
        || retired["held_descendants"] != serde_json::json!([])
    {
        return Err("policy gate retained unsettled native family".into());
    }
    for role in ["target", "namespace_init", "guardian"] {
        if retired[role] != prepared[role] {
            return Err("policy gate retired a substituted native process".into());
        }
        let record = &retired[format!("{role}_retirement")];
        closed(
            record,
            &[
                "pid",
                "birth",
                "parent_pid",
                "parent_birth",
                "retirement_observed",
            ],
        )?;
        if record["pid"] != prepared[role]["pid"]
            || record["birth"] != prepared[role]["birth"]
            || record["retirement_observed"] != true
            || !record["parent_pid"].is_null()
            || !record["parent_birth"].is_null()
        {
            return Err("policy gate independent PIDFD settlement differs".into());
        }
    }
    if scenario == "revoke-release" {
        let release = release.ok_or("final policy lease gate observation absent")?;
        closed(
            release,
            &["format", "revision", "prepared", "authorizes_launch"],
        )?;
        let release_ack = release_ack.ok_or("final policy lease gate acknowledgment absent")?;
        closed(
            release_ack,
            &[
                "format",
                "revision",
                "attempt_id",
                "admission_nonce",
                "target",
                "observer",
            ],
        )?;
        if release["format"] != "memcordon.mixed-release-observation"
            || release["revision"] != 2
            || release["prepared"] != *prepared
            || release["authorizes_launch"] != false
            || release_ack["format"] != "memcordon.mixed-release-observer-acknowledgment"
            || release_ack["revision"] != 2
            || release_ack["attempt_id"] != attempt
            || release_ack["admission_nonce"] != admission["admission_nonce"]
            || release_ack["target"] != prepared["target"]
            || release_ack["observer"] != native["observer"]
        {
            return Err(
                "final policy release gate differs from original held preparation/observer".into(),
            );
        }
    } else if release.is_some() || release_ack.is_some() {
        return Err("preparation gate substitutes final release instrumentation".into());
    }
    Ok(())
}

pub fn validate_linux_policy_command_capture(
    command: &Value,
    exit: &Value,
    command_bytes: &[u8],
    stdout: &[u8],
    stderr: &[u8],
    policy_bytes: &[u8],
    agent_sha256: &str,
) -> Result<(), String> {
    closed(
        command,
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
        exit,
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
    let program: Vec<u8> =
        serde_json::from_value(command["program"].clone()).map_err(|error| error.to_string())?;
    let arguments: Vec<Vec<u8>> =
        serde_json::from_value(command["arguments"].clone()).map_err(|error| error.to_string())?;
    let cwd: Vec<u8> =
        serde_json::from_value(command["cwd"].clone()).map_err(|error| error.to_string())?;
    if command["format"] != "memcordon.linux-policy-activation-command"
        || command["revision"] != 1
        || command["agent_sha256"] != agent_sha256
        || program != b"/usr/libexec/memcordon-sealed-agent"
        || arguments.len() != 5
        || arguments[..4]
            != [
                b"package".to_vec(),
                b"policy".to_vec(),
                b"apply".to_vec(),
                b"--file".to_vec(),
            ]
        || !arguments[4].starts_with(b"/var/lib/memcordon-consumer-readiness/")
        || arguments[4].contains(&0)
        || arguments[4]
            .split(|byte| *byte == b'/')
            .any(|part| part == b".." || part == b".")
        || !cwd.starts_with(b"/")
        || cwd.contains(&0)
        || command["environment_cleared"] != true
        || command["budget_millis"]
            .as_u64()
            .filter(|budget| *budget > 0 && *budget <= 60000)
            .is_none()
        || command["policy_sha256"] != crate::sha256(policy_bytes)
        || exit["format"] != "memcordon.linux-policy-activation-exit"
        || exit["revision"] != 1
        || exit["native_exit"] != 0
        || exit["success"] != true
        || exit["invocation_sha256"] != crate::sha256(command_bytes)
        || exit["stdout_sha256"] != crate::sha256(stdout)
        || exit["stderr_sha256"] != crate::sha256(stderr)
    {
        return Err("actual Linux policy command/capture/source association differs".into());
    }
    Ok(())
}

/// Bind the parser-produced public invocation to the actual retained setpriv
/// command. The native launch codec is a further, separate required join.
pub fn validate_linux_policy_frontend(
    command: &Value,
    public: &Value,
    challenge: &[u8],
    caller: u32,
    selected_cli_sha256: &str,
) -> Result<(), String> {
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
    closed(
        public,
        &[
            "syntax",
            "budget_tokens",
            "memory_token",
            "deadline_token",
            "argv",
        ],
    )?;
    let arguments: Vec<Vec<u8>> =
        serde_json::from_value(command["arguments"].clone()).map_err(|error| error.to_string())?;
    let program: Vec<u8> =
        serde_json::from_value(command["program"].clone()).map_err(|error| error.to_string())?;
    if command["format"] != "memcordon.linux-owned-frontend-invocation"
        || command["revision"] != 1
        || program != b"/usr/bin/setpriv"
        || arguments.len() != 23
        || command["environment_cleared"] != true
        || command["caller_uid"].as_u64() != Some(u64::from(caller))
        || command["caller_gid"].as_u64() != Some(u64::from(caller))
        || command["selected_cli_sha256"] != selected_cli_sha256
        || challenge.len() != 32
        || challenge.iter().all(|byte| *byte == 0)
    {
        return Err("policy public frontend native command/source/challenge differs".into());
    }
    let required = [
        (0, "--reuid"),
        (2, "--regid"),
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
    ];
    if required
        .into_iter()
        .any(|(index, value)| arguments[index] != value.as_bytes())
        || arguments[1] != caller.to_string().as_bytes()
        || arguments[3] != caller.to_string().as_bytes()
        || arguments[22] != hex::encode(challenge).as_bytes()
        || [11, 15, 17]
            .into_iter()
            .any(|index| !arguments[index].starts_with(b"/") || arguments[index].contains(&0))
    {
        return Err("policy public frontend argv differs from the frozen owned recipe".into());
    }
    let deadline =
        std::str::from_utf8(&arguments[8]).map_err(|_| "policy deadline token is not UTF-8")?;
    let millis = deadline
        .strip_prefix('+')
        .and_then(|text| text.strip_suffix("ms"))
        .and_then(|text| text.parse::<u64>().ok())
        .filter(|millis| *millis > 0 && *millis <= 30000)
        .ok_or("policy actual deadline token differs")?;
    if deadline != format!("+{millis}ms") {
        return Err("policy deadline token is not canonical".into());
    }
    let argv = vec![
        arguments[19].clone(),
        arguments[21].clone(),
        arguments[22].clone(),
    ];
    let actual_public = serde_json::json!({"syntax":"plus-budgets-v1",
        "budget_tokens":[{"kind":"memory","token":"+256M"},{"kind":"time","token":deadline}],
        "memory_token":"+256M","deadline_token":deadline,
        "argv":argv.into_iter().map(|bytes|std::str::from_utf8(&bytes).map(|text|serde_json::json!({"display":text,"raw":null}))).collect::<Result<Vec<_>,_>>().map_err(|_|"policy logical argv is not UTF-8")?});
    if *public != actual_public {
        return Err("policy parser-produced invocation differs from actual native command".into());
    }
    Ok(())
}

/// Validate an actual no-target public refusal without inventing retirement
/// facts for a target, guardian or private root that was never created.
pub fn validate_linux_policy_refusal_result(
    result: &Value,
    public_request_bytes: &[u8],
    requested_contract: &Value,
    public_invocation: &Value,
    version: &str,
    target: &str,
    frontend_status: i32,
    frontend_pid: u32,
    reason: &str,
) -> Result<(), String> {
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
    closed(
        &result["tool"],
        &["name", "version", "os", "architecture", "runtime_features"],
    )?;
    closed(
        &result["runtime"],
        &[
            "kind",
            "carrier_revision",
            "provider_contract",
            "launch_wire",
            "outcome",
        ],
    )?;
    closed(
        &result["frontend"],
        &["relay_drained", "interruption", "relay_error"],
    )?;
    let runtime = &result["runtime"];
    let outcome = &runtime["outcome"];
    closed(&result["delivery"], &["prepared-by"])?;
    closed(&result["delivery"]["prepared-by"], &["writer_pid"])?;
    if frontend_pid == 0
        || result["delivery"]["prepared-by"]["writer_pid"].as_u64() != Some(u64::from(frontend_pid))
    {
        return Err("public refusal lacks an actual prepared writer identity".into());
    }
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
    let request = crate::wire::json(public_request_bytes)?;
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
    let native = request["native_launch"]
        .as_array()
        .ok_or("public native launch absent")?;
    if request["format"] != "memcordon.mixed-runtime-request"
        || request["revision"] != 2
        || request["contract"] != *requested_contract
        || native.is_empty()
        || native
            .iter()
            .any(|byte| byte.as_u64().filter(|byte| *byte <= 255).is_none())
        || request["attempt_deadline_millis"]
            .as_u64()
            .filter(|deadline| *deadline > 0)
            .is_none()
        || result["format"] != "memcordon.result"
        || result["revision"] != 2
        || result["invocation"] != *public_invocation
        || result["wrapper_status"].as_i64() != Some(i64::from(frontend_status))
        || result["tool"]["name"] != "memcordon"
        || result["tool"]["version"] != version
        || result["tool"]["os"] != "linux"
        || result["tool"]["architecture"]
            != target.split('-').next().ok_or("native target absent")?
        || result["tool"]["runtime_features"]
            != serde_json::json!(["sealed-runtime", "private-tcp"])
        || runtime["kind"] != "linux-mixed-private"
        || runtime["carrier_revision"] != 2
        || runtime["provider_contract"] != 4
        || runtime["launch_wire"] != 4
        || outcome["kind"] != "rejected-before-authorization"
        || outcome["reason"] != reason
        || outcome["request_bytes_sha256"] != crate::sha256(public_request_bytes)
        || outcome["request_sha256"] != crate::wire::v3_request_digest(requested_contract)?
        || outcome["detail"]
            .as_str()
            .filter(|detail| !detail.is_empty() && detail.len() <= 4096)
            .is_none()
        || outcome["allocation"]["authorization"] != "never-authorized"
        || outcome["allocation"]["obligations"]
            .as_array()
            .is_none_or(|obligations| !obligations.is_empty())
        || result["frontend"]["relay_drained"] != true
        || !result["frontend"]["interruption"].is_null()
        || !result["frontend"]["relay_error"].is_null()
    {
        return Err(
            "actual no-target refusal crosses request/invocation/cause/native frontend association"
                .into(),
        );
    }
    Ok(())
}

pub(crate) fn activation_registry<'a>(receipt: &'a Value) -> Result<&'a Value, String> {
    let object = receipt
        .as_object()
        .ok_or("activation receipt is not an object")?;
    let fields = [
        "format",
        "revision",
        "registry",
        "registry_digest",
        "epoch",
        "revoked_admissions",
    ];
    if object.len() != fields.len()
        || fields.iter().any(|field| !object.contains_key(*field))
        || receipt["format"] != "memcordon.local-private-activation"
        || receipt["revision"] != 2
        || !receipt["registry"].is_object()
        || !receipt["revoked_admissions"].is_array()
    {
        return Err("activation receipt differs from the native V3 format".into());
    }
    crate::digest(
        receipt["registry_digest"]
            .as_str()
            .ok_or("activation registry digest absent")?,
    )?;
    native_epoch(&receipt["epoch"])?;
    let revoked = receipt["revoked_admissions"]
        .as_array()
        .ok_or("revoked admission array absent")?;
    let mut identities = std::collections::BTreeSet::new();
    if revoked.len() > 256 {
        return Err("activation revoked admissions exceed native bound".into());
    }
    for nonce in revoked {
        let bytes = nonce
            .as_array()
            .ok_or("revoked admission is not a native nonce")?;
        if bytes.len() != 16
            || bytes
                .iter()
                .any(|byte| byte.as_u64().filter(|byte| *byte <= 255).is_none())
            || !identities.insert(serde_json::to_string(nonce).map_err(|error| error.to_string())?)
        {
            return Err(
                "activation revoked admissions contain an invalid or duplicate native nonce".into(),
            );
        }
    }
    Ok(&receipt["registry"])
}

/// Bind mutations to actual retained activation and restoration receipts.
/// The caller must additionally check custody, successful command captures and
/// the registry's independently encoded digest; this function cannot replace them.
pub fn validate_linux_policy_activation_sequence(
    scenario: &str,
    baseline_registry: &Value,
    applied_registry: &Value,
    requested_contract: &Value,
    activation: &Value,
    restoration: &Value,
    earlier_activations: &[Value],
) -> Result<(), String> {
    if activation_registry(activation)? != applied_registry
        || activation_registry(restoration)? != baseline_registry
    {
        return Err(
            "activation/restoration does not retain the exact applied/original registry".into(),
        );
    }
    let active = &activation["epoch"];
    let restored = &restoration["epoch"];
    if active["service_instance"] != restored["service_instance"]
        || restored["revision"].as_u64() <= active["revision"].as_u64()
    {
        return Err(
            "restoration does not follow the actual activation in the same service instance".into(),
        );
    }
    native_epoch(&requested_contract["expected_epoch"])?;
    if scenario == "wrong-epoch" {
        if earlier_activations.is_empty() || earlier_activations.len() > 64 {
            return Err("stale request lacks a bounded earlier activation source".into());
        }
        let mut found = false;
        for earlier in earlier_activations {
            if activation_registry(earlier)? != baseline_registry {
                return Err("earlier activation does not retain the original registry".into());
            }
            let epoch = &earlier["epoch"];
            if epoch["service_instance"] != active["service_instance"]
                || epoch["revision"].as_u64() >= active["revision"].as_u64()
            {
                return Err(
                    "earlier activation is not earlier in the actual service instance".into(),
                );
            }
            found |= requested_contract["expected_epoch"] == *epoch;
        }
        if !found {
            return Err("stale request epoch is not an actual retained earlier activation".into());
        }
    } else if requested_contract["expected_epoch"] != *active {
        return Err("request epoch differs from the actual activation".into());
    }
    Ok(())
}

/// Decode only the exact nine installed binding mutations. Native invocation,
/// provider refusal and restoration custody are separate mandatory joins.
pub fn validate_linux_policy_mutation(
    scenario: &str,
    baseline_registry: &Value,
    applied_registry: &Value,
    baseline_contract: &Value,
    requested_contract: &Value,
    applied_epoch: &Value,
    caller_uid: u32,
    observed_reason: &str,
) -> Result<(), String> {
    let reason = match scenario {
        "wrong-caller" => "unauthorized-caller",
        "wrong-plan" => "unauthorized-plan",
        "wrong-image" | "wrong-digest" => "unauthorized-image",
        "wrong-profile" => "unauthorized-profile",
        "wrong-identity" => "unauthorized-identity",
        "wrong-epoch" | "revoke-discovery" | "revoke-preparation" | "revoke-release" => {
            "stale-epoch"
        }
        "disabled-grant" => "disabled-grant",
        "changed-grant" => "wrong-grant-revision",
        _ => return Err("unfrozen Linux binding mutation".into()),
    };
    let grants = baseline_registry["grants"]
        .as_array()
        .ok_or("baseline grants absent")?;
    if grants.len() != 1 || grants[0]["enabled"] != true || grants[0]["revision"] != 1 {
        return Err("binding mutation requires one enabled original revision-one grant".into());
    }
    if !baseline_contract.is_object()
        || !requested_contract.is_object()
        || !applied_epoch.is_object()
        || !grants[0].is_object()
        || [
            "authorization",
            "runtime_image",
            "authorized_profile",
            "execution_identity",
            "expected_epoch",
        ]
        .iter()
        .any(|field| !baseline_contract[*field].is_object())
        || !baseline_contract["execution_identity"]["identity"].is_object()
        || !requested_contract["expected_epoch"].is_object()
    {
        return Err("binding contract/epoch shape differs".into());
    }
    let mut expected_registry = baseline_registry.clone();
    match scenario {
        "disabled-grant" => expected_registry["grants"][0]["enabled"] = false.into(),
        "changed-grant" => expected_registry["grants"][0]["revision"] = 2.into(),
        _ => {}
    }
    if applied_registry != &expected_registry {
        return Err("binding mutation changed unrelated original registry data".into());
    }
    let mut expected = baseline_contract.clone();
    expected["expected_epoch"] = applied_epoch.clone();
    let changed_digest = hex::encode(Sha256::digest(scenario.as_bytes()));
    match scenario {
        "wrong-plan" => {
            expected["workload_plan_digest"] = changed_digest.clone().into();
            expected["authorization"]["approved_plan_digest"] = changed_digest.into();
        }
        "wrong-image" => expected["runtime_image"]["id"] = "owned-readiness-wrong-image".into(),
        "wrong-profile" => {
            expected["authorized_profile"]["semantic_digest"] = changed_digest.into()
        }
        "wrong-identity" => {
            expected["execution_identity"]["identity"]["digest"] = changed_digest.into()
        }
        "wrong-digest" => expected["runtime_image"]["digest"] = changed_digest.into(),
        "wrong-epoch" => {
            // The stale epoch comes from an earlier actual activation receipt;
            // its custody is checked by the caller, never guessed here.
            if requested_contract["expected_epoch"] == *applied_epoch {
                return Err("stale-epoch mutation retained the current epoch".into());
            }
            expected["expected_epoch"] = requested_contract["expected_epoch"].clone();
        }
        _ => {}
    }
    if requested_contract != &expected
        || observed_reason != reason
        || caller_uid
            != if scenario == "wrong-caller" {
                65533
            } else {
                65534
            }
    {
        return Err("binding request/caller/refusal differs from exact selected mutation".into());
    }
    Ok(())
}
