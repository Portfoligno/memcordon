//! Exercise local grants against the actual installed Linux payload.
use std::{
    ffi::OsString,
    fs,
    num::{NonZeroU32, NonZeroU64},
    path::Path,
    time::Duration,
};

use super::{
    artifacts,
    installed_consumer::{MaterializedPayload, binary_path},
    source,
};
use crate::{CiError, Result, command::CommandSpec};
use memcordon_core::{
    BoundedText, BoundedVec, DiagnosticSha256,
    result_v1::{CleanupStateV1, OutcomeKindV1, ResultV1},
    workload_contract::{
        AuthorizationRef, ContractVersionTwo, ExecutionIdentityRefV2, ExecutionIdentityRequestV2,
        LogicalId, PolicyEpoch, WorkloadContractV2,
    },
    workload_registry::{CallerSelector, GrantChangeDisposition},
    workload_registry_v2::{
        ApprovedEntrypointV2, LinuxExecutionIdentityV2, PolicyGrantV2, ProfileKindV2,
        RuntimePrivatePolicyRegistry, RuntimePrivateProfileDefinition,
    },
};
use sha2::Digest;

const CLI: &str = "/usr/libexec/memcordon";
const AGENT: &str = "/usr/libexec/memcordon-sealed-agent";
const FIXTURE: &str = "/usr/libexec/memcordon-installed-private-fixture";
const FIXTURE_RECEIPT: &str = "/usr/libexec/memcordon-installed-private-fixture.memcordon-receipt";
const INSTALL_DEFINITION: &str = "/usr/libexec/memcordon-installed-private-definition.json";
const CALLER: u32 = 65534;
const DELEGATED: u32 = 65533;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PrivateFixtureObservation {
    format: String,
    revision: u32,
    uid: [u32; 4],
    gid: [u32; 4],
    groups: Vec<u32>,
    no_new_privileges: bool,
    capabilities: std::collections::BTreeMap<String, String>,
    entry_fds: Vec<i32>,
    network_namespace: String,
    ipv6_addresses: u32,
    tcp_port: u16,
    tcp_bytes: String,
    denied: Vec<String>,
}

/// Native fixture facts are checked independently of the reported request.
pub fn validate_private_fixture(
    bytes: &[u8],
    uid: u32,
    gid: u32,
    groups: &[u32],
    host_namespace_inode: u64,
) -> Result<u64> {
    if bytes.len() > 64 * 1024 {
        return Err(CiError::Message(
            "private native observation exceeds bound".into(),
        ));
    }
    memcordon_core::canonical_json::reject_duplicate_json_keys(bytes).map_err(CiError::Message)?;
    let value: PrivateFixtureObservation = serde_json::from_slice(bytes)?;
    let namespace_inode = value
        .network_namespace
        .strip_prefix("net:[")
        .and_then(|value| value.strip_suffix(']'))
        .and_then(|value| value.parse::<u64>().ok())
        .ok_or_else(|| CiError::Message("private native namespace identity malformed".into()))?;
    let denied = [
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
        "clone-detached",
    ];
    let sets = ["CapAmb", "CapBnd", "CapEff", "CapInh", "CapPrm"];
    if value.format != "memcordon.private-native-fixture"
        || value.revision != 1
        || value.uid != [uid; 4]
        || value.gid != [gid; 4]
        || value.groups != groups
        || !value.no_new_privileges
        || value.entry_fds != [0, 1, 2]
        || value.capabilities.len() != sets.len()
        || sets.iter().any(|name| {
            value
                .capabilities
                .get(*name)
                .is_none_or(|value| u64::from_str_radix(value, 16).ok() != Some(0))
        })
        || namespace_inode == 0
        || namespace_inode == host_namespace_inode
        || value.ipv6_addresses != 0
        || !(32768..=60999).contains(&value.tcp_port)
        || value.tcp_bytes != "private"
        || value.denied.iter().map(String::as_str).ne(denied)
    {
        return Err(CiError::Message(
            "private native credentials/namespace/resources/filter/TCP facts differ".into(),
        ));
    }
    Ok(namespace_inode)
}

#[derive(serde::Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
enum ListenerObservation {
    Ready {
        format: String,
        revision: u32,
        bound_port: u16,
        competitor: String,
    },
    Completed {
        format: String,
        revision: u32,
        bound_port: u16,
        http_body: String,
        server_joined: bool,
    },
    ListenerPolicyFailure {
        format: String,
        revision: u32,
        bound_port: u16,
        requested_port: u16,
        readiness_emitted: bool,
        dispatch_started: bool,
    },
}

/// These facts come from the trusted native fixture, independently of the
/// provider report. The negative anchor must have bound before policy denial.
pub fn validate_tcp_anchor(bytes: &[u8], policy_failure: bool) -> Result<()> {
    if bytes.len() > 4096 || !bytes.ends_with(b"\n") {
        return Err(CiError::Message(
            "listener anchor is truncated or oversized".into(),
        ));
    }
    let mut observations = Vec::new();
    for line in bytes
        .strip_suffix(b"\n")
        .expect("checked LF")
        .split(|byte| *byte == b'\n')
    {
        memcordon_core::canonical_json::reject_duplicate_json_keys(line)
            .map_err(CiError::Message)?;
        observations.push(serde_json::from_slice::<ListenerObservation>(line)?);
    }
    let valid_format =
        |format: &str, revision: u32| format == "memcordon.prebound-listener" && revision == 1;
    let valid_port = |port| (32768..=60999).contains(&port);
    let valid = match observations.as_slice() {
        [
            ListenerObservation::ListenerPolicyFailure {
                format,
                revision,
                bound_port,
                requested_port,
                readiness_emitted,
                dispatch_started,
            },
        ] if policy_failure => {
            valid_format(format, *revision)
                && valid_port(*bound_port)
                && *requested_port != 0
                && requested_port != bound_port
                && !readiness_emitted
                && !dispatch_started
        }
        [
            ListenerObservation::Ready {
                format,
                revision,
                bound_port,
                competitor,
            },
            ListenerObservation::Completed {
                format: completed_format,
                revision: completed_revision,
                bound_port: completed_port,
                http_body,
                server_joined,
            },
        ] if !policy_failure => {
            valid_format(format, *revision)
                && valid_format(completed_format, *completed_revision)
                && valid_port(*bound_port)
                && bound_port == completed_port
                && competitor == "address-in-use"
                && http_body == "owned"
                && *server_joined
        }
        _ => false,
    };
    if !valid {
        return Err(CiError::Message(
            "listener ownership/readiness/typed policy facts differ".into(),
        ));
    }
    Ok(())
}

fn sudo(cwd: &Path, arguments: &[OsString]) -> Result<Vec<u8>> {
    CommandSpec::new("sudo", cwd, Duration::from_secs(90))
        .arg("-n")
        .args(arguments)
        .run()
}

fn identifier(value: &str) -> Result<LogicalId> {
    LogicalId::new(value.into()).map_err(CiError::Message)
}

fn bounded<T, const N: usize>(values: impl IntoIterator<Item = T>) -> Result<BoundedVec<T, N>> {
    let mut result = BoundedVec::default();
    for value in values {
        result
            .try_push(value)
            .map_err(|_| CiError::Message("installed case exceeds model bound".into()))?;
    }
    Ok(result)
}

fn registry(payload: &MaterializedPayload) -> Result<RuntimePrivatePolicyRegistry> {
    let digest = DiagnosticSha256::from_bytes(
        sha2::Sha256::digest(artifacts::read_file(&payload.fixture.path)?).into(),
    );
    let mut identity = LinuxExecutionIdentityV2 {
        reference: ExecutionIdentityRefV2 {
            id: identifier("installed-delegated")?,
            semantic_digest: digest.clone(),
        },
        enabled: true,
        uid: NonZeroU32::new(DELEGATED).expect("fixed nonroot UID"),
        gid: NonZeroU32::new(DELEGATED).expect("fixed nonroot GID"),
        supplementary_groups: BoundedVec::default(),
        entrypoints: bounded([ApprovedEntrypointV2 {
            id: identifier("installed-fixture")?,
            absolute_path: BoundedText::new(FIXTURE)
                .map_err(|error| CiError::Message(error.into()))?,
            sha256: digest.clone(),
            size: NonZeroU64::new(fs::metadata(&payload.fixture.path)?.len())
                .ok_or_else(|| CiError::Message("empty installed fixture".into()))?,
        }])?,
    };
    identity.reference.semantic_digest = identity.semantic_digest().map_err(CiError::Message)?;
    let profile = ProfileKindV2::LinuxTcp4PrivateV1;
    let identities = [
        ExecutionIdentityRequestV2::PreserveCaller,
        ExecutionIdentityRequestV2::AdministratorProfile {
            reference: identity.reference.clone(),
        },
    ];
    let mut grants = Vec::new();
    for (name, execution_identity) in ["installed-preserved", "installed-delegated"]
        .into_iter()
        .zip(identities)
    {
        grants.push(PolicyGrantV2 {
            id: identifier(name)?,
            revision: NonZeroU64::MIN,
            profile: profile.reference(),
            ceiling: profile.ceiling(),
            enabled: true,
            callers: bounded([CallerSelector::Linux { uid: CALLER }])?,
            approved_plans: bounded([digest.clone()])?,
            execution_identity,
        });
    }
    let value = RuntimePrivatePolicyRegistry {
        format: "memcordon.local-private-policy".into(),
        revision: 1,
        profiles: bounded([RuntimePrivateProfileDefinition {
            profile,
            reference: profile.reference(),
            enabled: true,
        }])?,
        execution_identities: bounded([identity])?,
        grants: bounded(grants)?,
        active_attempt_disposition: GrantChangeDisposition::DrainExisting,
    };
    value.validate().map_err(CiError::Message)?;
    Ok(value)
}

#[expect(
    clippy::too_many_arguments,
    reason = "native cases keep selected inputs and expected outcome facts explicit"
)]
fn execute(
    payload: &MaterializedPayload,
    cwd: &Path,
    output: &Path,
    group: &str,
    name: &str,
    contract: &WorkloadContractV2,
    fixture_arguments: &[OsString],
    deadline: bool,
    expected_status: i32,
) -> Result<ResultV1> {
    execute_observed(
        payload,
        cwd,
        output,
        group,
        name,
        contract,
        fixture_arguments,
        deadline,
        expected_status,
        if deadline {
            OutcomeKindV1::Deadline
        } else {
            OutcomeKindV1::Completed
        },
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "native cases keep selected inputs and independent outcome assertions explicit"
)]
fn execute_observed(
    payload: &MaterializedPayload,
    cwd: &Path,
    output: &Path,
    group: &str,
    name: &str,
    contract: &WorkloadContractV2,
    fixture_arguments: &[OsString],
    deadline: bool,
    expected_status: i32,
    expected_outcome: OutcomeKindV1,
) -> Result<ResultV1> {
    execute_options(
        payload,
        cwd,
        output,
        group,
        name,
        contract,
        fixture_arguments,
        deadline,
        expected_status,
        expected_outcome,
        &[],
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "native cases retain exact argv separately from expected outcome facts"
)]
fn execute_options(
    payload: &MaterializedPayload,
    cwd: &Path,
    output: &Path,
    group: &str,
    name: &str,
    contract: &WorkloadContractV2,
    fixture_arguments: &[OsString],
    deadline: bool,
    expected_status: i32,
    expected_outcome: OutcomeKindV1,
    options: &[&str],
) -> Result<ResultV1> {
    execute_controlled(
        payload,
        cwd,
        output,
        group,
        name,
        contract,
        fixture_arguments,
        deadline,
        expected_status,
        expected_outcome,
        options,
        false,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "owned native execution joins exact inputs, interruption and independently expected terminal facts"
)]
fn execute_controlled(
    payload: &MaterializedPayload,
    cwd: &Path,
    output: &Path,
    group: &str,
    name: &str,
    contract: &WorkloadContractV2,
    fixture_arguments: &[OsString],
    deadline: bool,
    expected_status: i32,
    expected_outcome: OutcomeKindV1,
    options: &[&str],
    interrupt: bool,
) -> Result<ResultV1> {
    let request_path = cwd.join(name).with_extension("request.json");
    source::write_json(&request_path, contract)?;
    let report_path = cwd.join("reports").join(name).with_extension("json");
    let mut arguments: Vec<OsString> = if interrupt {
        // GNU timeout retains its own direct child, which setpriv execs into
        // the actual frontend; it sends SIGINT without PID discovery.
        [
            "/usr/bin/timeout",
            "--preserve-status",
            "--signal=INT",
            "--kill-after=5s",
            "5s",
        ]
        .into_iter()
        .map(OsString::from)
        .collect()
    } else {
        Vec::new()
    };
    arguments.extend([
        "setpriv".into(),
        "--reuid".into(),
        CALLER.to_string().into(),
        "--regid".into(),
        CALLER.to_string().into(),
        "--groups".into(),
        group.into(),
        "--bounding-set=-all".into(),
        "--inh-caps=-all".into(),
        "--ambient-caps=-all".into(),
        "--no-new-privs".into(),
        CLI.into(),
        "--sealed".into(),
        "--workload-contract".into(),
        request_path.into_os_string(),
        "--report-format".into(),
        "result-v1".into(),
        "--report".into(),
        report_path.as_os_str().to_os_string(),
    ]);
    if deadline {
        arguments.push("+200ms".into());
    }
    arguments.extend(options.iter().map(OsString::from));
    arguments.extend(["--".into(), FIXTURE.into()]);
    arguments.extend_from_slice(fixture_arguments);
    let mut command = CommandSpec::new("sudo", cwd, Duration::from_secs(60))
        .arg("-n")
        .args(arguments)
        .materialize()?;
    let observed = memcordon_testkit::run_with_deadline_output_limit(
        &mut command,
        Duration::from_secs(60),
        1024 * 1024,
    )
    .map_err(|error| CiError::Message(error.to_string()))?;
    fs::write(
        output.join(name).with_extension("stdout.bin"),
        &observed.stdout,
    )?;
    fs::write(
        output.join(name).with_extension("stderr.bin"),
        &observed.stderr,
    )?;
    let bytes = sudo(cwd, &["cat".into(), report_path.into_os_string()])?;
    fs::write(output.join(name).with_extension("json"), &bytes)?;
    let result = ResultV1::parse(&bytes).map_err(CiError::Message)?;
    if options.contains(&"supervision") {
        if observed.status.code() != Some(123)
            || result.outcome.wrapper_status != 123
            || result.outcome.kind != OutcomeKindV1::Deadline
            || result.launch.state != memcordon_core::result_v1::LaunchStateV1::NotCreated
            || result.authorization
                != memcordon_core::result_v1::AuthorizationV1::RejectedBeforeRelease
            || result.private_execution.is_some()
            || result.launch.target_pid.is_some()
            || result.outcome.native_termination.is_some()
            || result.cleanup.direct_child_reaped
        {
            return Err(CiError::Message(
                "expired original supervision budget allocated or authorized a target".into(),
            ));
        }
        return Ok(result);
    }
    if expected_outcome == OutcomeKindV1::Unknown {
        if result.tool.version != payload.source.version().to_string()
            || observed.status.code() != Some(expected_status)
            || result.outcome.wrapper_status != expected_status
            || result.outcome.kind != OutcomeKindV1::Unknown
            || result.launch.state != memcordon_core::result_v1::LaunchStateV1::Unknown
            || result.authorization != memcordon_core::result_v1::AuthorizationV1::Uncertain
            || result.cleanup.state != CleanupStateV1::Unknown
            || result.private_execution.is_some()
            || result.private_rejection.is_some()
            || result.cleanup.direct_child_reaped
        {
            return Err(CiError::Message(
                "lost native transaction invented authorization, termination or cleanup".into(),
            ));
        }
        return Ok(result);
    }
    let execution = result.private_execution.as_ref().ok_or_else(|| {
        CiError::Message("installed private execution has no native terminal".into())
    })?;
    let manifest_bytes = artifacts::read_file(&payload.directory.join("runtime-manifest.json"))?;
    let manifest = memcordon_core::runtime_manifest::RuntimeManifest::parse(&manifest_bytes)
        .map_err(CiError::Message)?;
    let provider = manifest
        .public_binding(&manifest_bytes)
        .map_err(CiError::Message)?;
    if result.tool.version != payload.source.version().to_string()
        || observed.status.code() != Some(result.outcome.wrapper_status)
        || result.outcome.wrapper_status != expected_status
        || execution.terminal.provider != provider
        || execution.terminal.admission_metadata.request != *contract
        || !execution.terminal.exec_observed
            && !options.contains(&"+0ms")
            && !options.contains(&"+1ms")
        || execution.terminal.exec_observed
            && execution.terminal.post_exec_descriptor_count != Some(3)
        || !execution.terminal.exec_observed
            && execution.terminal.post_exec_descriptor_count.is_some()
        || execution.cleanup_state() != CleanupStateV1::Complete
        || result.cleanup.state != CleanupStateV1::Complete
        || result.outcome.kind != expected_outcome
        || expected_outcome == OutcomeKindV1::Completed
            && execution.terminal.native_termination
                != Some(memcordon_core::ChildTermination::ExitCode {
                    code: expected_status,
                })
    {
        return Err(CiError::Message(
            "installed private native request/exec/outcome/retirement association differs".into(),
        ));
    }
    Ok(result)
}

#[cfg(target_os = "linux")]
fn host_network_snapshot() -> Result<serde_json::Value> {
    use std::os::unix::fs::MetadataExt;
    let namespace = fs::metadata("/proc/self/ns/net")?;
    let mut facts = std::collections::BTreeMap::new();
    for path in [
        "/proc/sys/net/ipv4/ip_local_port_range",
        "/proc/sys/net/ipv4/ip_local_reserved_ports",
        "/proc/sys/net/ipv4/ip_nonlocal_bind",
        "/proc/sys/net/ipv6/conf/all/disable_ipv6",
        "/proc/net/route",
        "/proc/net/ipv6_route",
    ] {
        let value = match fs::read(path) {
            Ok(bytes) => Some(bytes),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(error.into()),
        };
        facts.insert(path, value);
    }
    let mut links = std::collections::BTreeMap::new();
    for entry in fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| CiError::Message("host link name is not UTF-8".into()))?;
        let mut values = std::collections::BTreeMap::new();
        for leaf in ["ifindex", "address", "flags", "operstate"] {
            values.insert(leaf, fs::read(entry.path().join(leaf))?);
        }
        links.insert(name, values);
    }
    Ok(
        serde_json::json!({"namespace_device":namespace.dev(), "namespace_inode":namespace.ino(), "facts":facts, "links":links}),
    )
}

#[cfg(target_os = "linux")]
fn installed_owner_loss_cases(
    payload: &MaterializedPayload,
    cwd: &Path,
    output: &Path,
    group: &str,
    contracts: &[WorkloadContractV2],
) -> Result<()> {
    for (contract, names) in contracts.iter().zip([
        [
            ("init", "preserved-init-loss"),
            ("worker", "preserved-worker-loss"),
        ],
        [
            ("init", "delegated-init-loss"),
            ("worker", "delegated-worker-loss"),
        ],
    ]) {
        for (mode, name) in names {
            let ready = cwd.join("markers").join(name).with_extension("identity");
            let observation = cwd.join("markers").join(name).with_extension("observation");
            let acknowledged = cwd.join("markers").join(name).with_extension("assessed");
            let request = cwd.join(name).with_extension("request.json");
            let arguments = [
                "hold".into(),
                "--duration".into(),
                "30s".into(),
                "--pid-file".into(),
                ready.as_os_str().to_os_string(),
            ];
            let until = std::time::Instant::now() + Duration::from_secs(25);
            std::thread::scope(|scope| -> Result<()> {
                let native = std::thread::Builder::new().spawn_scoped(scope, || {
                    execute_options(
                        payload,
                        cwd,
                        output,
                        group,
                        name,
                        contract,
                        &arguments,
                        false,
                        125,
                        if mode == "worker" {
                            OutcomeKindV1::Unknown
                        } else {
                            OutcomeKindV1::ProviderFailure
                        },
                        &[],
                    )
                })?;
                while !ready.try_exists()? {
                    if std::time::Instant::now() >= until {
                        let _ = native.join();
                        return Err(CiError::Message(
                            "installed loss target did not publish actual native identity".into(),
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                let observer = std::thread::Builder::new().spawn_scoped(scope, || {
                    CommandSpec::new("sudo", cwd, Duration::from_secs(30))
                        .arg("-n")
                        .arg(&payload.fixture.path)
                        .arg("private-installed-owner-loss")
                        .arg(&request)
                        .arg(&ready)
                        .arg(mode)
                        .arg(&payload.fixture.sha256)
                        .arg(&observation)
                        .arg(&acknowledged)
                        .output_quiet()
                });
                let execution = native
                    .join()
                    .map_err(|_| CiError::Message("installed loss native owner panicked".into()))?;
                let assessment = (|| -> Result<()> {
                    while !observation.try_exists()? {
                        if std::time::Instant::now() >= until {
                            return Err(CiError::Message(
                                "held native loss observation absent".into(),
                            ));
                        }
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    let bytes = fs::read(&observation)?;
                    fs::write(
                        output.join(name).with_extension("native-observation.json"),
                        &bytes,
                    )?;
                    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes)
                        .map_err(CiError::Message)?;
                    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
                    if value.get("mode").and_then(serde_json::Value::as_str) != Some(mode)
                        || value
                            .get("retirement_observed")
                            .and_then(serde_json::Value::as_bool)
                            != Some(true)
                        || mode == "worker"
                            && value
                                .get("runtime_quarantine_retained")
                                .and_then(serde_json::Value::as_bool)
                                != Some(true)
                    {
                        return Err(CiError::Message(
                            "native loss did not retain independent real process/cgroup facts"
                                .into(),
                        ));
                    }
                    execution
                        .as_ref()
                        .map_err(|error| CiError::Message(error.to_string()))?;
                    if mode == "worker" {
                        let busy = if name == "preserved-worker-loss" {
                            "preserved-after-loss-busy"
                        } else {
                            "delegated-after-loss-busy"
                        };
                        reject_launch_state(
                            payload, cwd, output, group, busy, CALLER, contract, true,
                        )?;
                    }
                    Ok(())
                })();
                let acknowledged = fs::write(&acknowledged, b"assessed\n");
                let observed = observer
                    .map_err(CiError::from)?
                    .join()
                    .map_err(|_| CiError::Message("native loss observer panicked".into()))??;
                fs::write(
                    output.join(name).with_extension("observer.stdout.bin"),
                    &observed.stdout,
                )?;
                fs::write(
                    output.join(name).with_extension("observer.stderr.bin"),
                    &observed.stderr,
                )?;
                if !observed.status.success() {
                    return Err(CiError::Message(
                        "independent held native loss observer failed".into(),
                    ));
                }
                assessment?;
                acknowledged?;
                Ok(())
            })?;
        }
    }
    Ok(())
}

fn descendant_and_restart_cases(
    payload: &MaterializedPayload,
    cwd: &Path,
    output: &Path,
    group: &str,
    contract: &WorkloadContractV2,
    prefix: &str,
) -> Result<()> {
    let names = match prefix {
        "preserved-lifetime" => [
            "preserved-command",
            "preserved-workload",
            "preserved-restart",
        ],
        "delegated-lifetime" => [
            "delegated-command",
            "delegated-workload",
            "delegated-restart",
        ],
        _ => return Err(CiError::Message("unknown installed identity case".into())),
    };
    for (mode, name) in ["command", "workload"].into_iter().zip(names) {
        let child = cwd.join("markers").join(name).with_extension("child.json");
        let completed = cwd.join("markers").join(name).with_extension("completed");
        execute_options(
            payload,
            cwd,
            output,
            group,
            name,
            contract,
            &[
                "spawn-background".into(),
                "--child-duration".into(),
                "500ms".into(),
                "--pid-file".into(),
                child.into_os_string(),
                "--completion-marker".into(),
                completed.as_os_str().to_os_string(),
            ],
            false,
            0,
            OutcomeKindV1::Completed,
            &["--wait-for", mode],
        )?;
        if (mode == "workload") != completed.exists() {
            return Err(CiError::Message(
                "command/workload descendant lifetime differs".into(),
            ));
        }
    }
    let name = names[2];
    let result = execute_options(
        payload,
        cwd,
        output,
        group,
        name,
        contract,
        &["hold".into(), "--duration".into(), "10s".into()],
        true,
        123,
        OutcomeKindV1::Deadline,
        &["--restart-on", "deadline", "--restart-limit", "1"],
    )?;
    if result.attempts.len() != 2 {
        return Err(CiError::Message(
            "finite restart must retain both actual attempts".into(),
        ));
    }
    let mut identities = std::collections::BTreeSet::new();
    for attempt in &result.attempts {
        let execution = attempt.private_execution.as_ref().ok_or_else(|| {
            CiError::Message("restart history lost its native private terminal".into())
        })?;
        if execution.cleanup_state() != CleanupStateV1::Complete
            || execution.terminal.outcome != OutcomeKindV1::Deadline
            || execution.terminal.admission_metadata.request != *contract
            || !execution.terminal.exec_observed
            || !identities.insert(execution.terminal.attempt_id)
        {
            return Err(CiError::Message(
                "restart did not independently grant, execute and retire both attempts".into(),
            ));
        }
    }
    for (name, budget, scope) in [
        (
            if prefix == "preserved-lifetime" {
                "preserved-zero-attempt"
            } else {
                "delegated-zero-attempt"
            },
            "+0ms",
            "attempt",
        ),
        (
            if prefix == "preserved-lifetime" {
                "preserved-tiny-attempt"
            } else {
                "delegated-tiny-attempt"
            },
            "+1ms",
            "attempt",
        ),
        (
            if prefix == "preserved-lifetime" {
                "preserved-zero-supervision"
            } else {
                "delegated-zero-supervision"
            },
            "+0ms",
            "supervision",
        ),
    ] {
        execute_options(
            payload,
            cwd,
            output,
            group,
            name,
            contract,
            &["hold".into(), "--duration".into(), "10s".into()],
            false,
            123,
            OutcomeKindV1::Deadline,
            &[budget, "--deadline-scope", scope],
        )?;
    }
    Ok(())
}

fn activate(
    cwd: &Path,
    output: &Path,
    name: &str,
    registry: &RuntimePrivatePolicyRegistry,
) -> Result<PolicyEpoch> {
    let path = cwd.join(name).with_extension("policy.json");
    source::write_json(&path, registry)?;
    let bytes = sudo(
        cwd,
        &[
            AGENT.into(),
            "package".into(),
            "policy".into(),
            "apply".into(),
            "--file".into(),
            path.into_os_string(),
        ],
    )?;
    fs::write(output.join(name).with_extension("activation.json"), &bytes)?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&bytes).map_err(CiError::Message)?;
    let value: serde_json::Value = serde_json::from_slice(&bytes)?;
    serde_json::from_value(
        value
            .get("epoch")
            .cloned()
            .ok_or_else(|| CiError::Message("activation omitted actual epoch".into()))?,
    )
    .map_err(CiError::from)
}

fn wait_ready(path: &Path, until: std::time::Instant) -> Result<()> {
    loop {
        match fs::read(path) {
            Ok(bytes) if bytes == b"authorized\n" => return Ok(()),
            Ok(_) => {
                return Err(CiError::Message(
                    "native gate readiness bytes differ".into(),
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        if std::time::Instant::now() >= until {
            return Err(CiError::Message(
                "native private target readiness deadline elapsed".into(),
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "native lifetime cases bind installed paths, identity, contract and grant disposition independently"
)]
fn grant_lifetime(
    payload: &MaterializedPayload,
    cwd: &Path,
    output: &Path,
    group: &str,
    registry: &RuntimePrivatePolicyRegistry,
    contract: &WorkloadContractV2,
    name: &str,
    revoke: bool,
) -> Result<PolicyEpoch> {
    let ready = cwd.join("markers").join(name).with_extension("ready");
    let finish = cwd.join("markers").join(name).with_extension("finish");
    let arguments = [
        OsString::from("gate-wait"),
        ready.as_os_str().to_os_string(),
        finish.as_os_str().to_os_string(),
    ];
    let mut changed = registry.clone();
    changed.grants = bounded(registry.grants.as_slice().iter().cloned().map(|mut grant| {
        if grant.id == contract.authorization.grant_id {
            grant.enabled = false;
        }
        grant
    }))?;
    changed.active_attempt_disposition = if revoke {
        GrantChangeDisposition::RevokeActive
    } else {
        GrantChangeDisposition::DrainExisting
    };
    let until = std::time::Instant::now() + Duration::from_secs(15);
    let execution = std::thread::scope(|scope| -> Result<()> {
        let owner = std::thread::Builder::new().spawn_scoped(scope, || {
            execute_observed(
                payload,
                cwd,
                output,
                group,
                name,
                contract,
                &arguments,
                false,
                if revoke { 125 } else { 0 },
                if revoke {
                    OutcomeKindV1::Interrupted
                } else {
                    OutcomeKindV1::Completed
                },
            )
        })?;
        let coordination = (|| {
            wait_ready(&ready, until)?;
            let epoch = activate(cwd, output, name, &changed)?;
            let mut denied = contract.clone();
            denied.expected_epoch = epoch;
            let rejection_name = match name {
                "preserved-drain" => "preserved-drain-new-launch",
                "delegated-drain" => "delegated-drain-new-launch",
                "preserved-revoke" => "preserved-revoke-new-launch",
                "delegated-revoke" => "delegated-revoke-new-launch",
                _ => return Err(CiError::Message("unknown lifetime case".into())),
            };
            reject_launch(payload, cwd, output, group, rejection_name, CALLER, &denied)?;
            if !revoke {
                fs::write(&finish, b"finish\n")?;
            }
            Ok::<(), CiError>(())
        })();
        // A failed coordinator still allows the bounded workload owner to finish;
        // its native terminal and retirement assessment are never detached.
        if coordination.is_err() {
            let _ = fs::write(&finish, b"finish\n");
        }
        let observed = owner
            .join()
            .map_err(|_| CiError::Message("private lifetime owner panicked".into()))?;
        match (coordination, observed) {
            (Ok(()), Ok(_)) => Ok(()),
            (Err(first), Err(second)) => Err(CiError::Message(format!(
                "private lifetime coordination: {first}; native execution: {second}"
            ))),
            (Err(error), _) | (_, Err(error)) => Err(error),
        }
    });
    // Restore from an ordinary fresh activation, never from the saved old epoch.
    let restored = activate(
        cwd,
        output,
        if revoke {
            "restore-after-revoke"
        } else {
            "restore-after-drain"
        },
        registry,
    );
    match (execution, restored) {
        (Ok(()), Ok(epoch)) => Ok(epoch),
        (Err(first), Err(second)) => Err(CiError::Message(format!(
            "private lifetime: {first}; policy restoration: {second}"
        ))),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

fn concurrent_attempts(
    payload: &MaterializedPayload,
    cwd: &Path,
    output: &Path,
    group: &str,
    first: &WorkloadContractV2,
    second: &WorkloadContractV2,
) -> Result<()> {
    let ready = [
        cwd.join("markers/concurrent-preserved.ready"),
        cwd.join("markers/concurrent-delegated.ready"),
    ];
    let finish = [
        cwd.join("markers/concurrent-preserved.finish"),
        cwd.join("markers/concurrent-delegated.finish"),
    ];
    let args = ready
        .iter()
        .zip(&finish)
        .map(|(ready, finish)| {
            [
                OsString::from("gate-wait"),
                ready.as_os_str().to_os_string(),
                finish.as_os_str().to_os_string(),
            ]
        })
        .collect::<Vec<_>>();
    let until = std::time::Instant::now() + Duration::from_secs(15);
    std::thread::scope(|scope| {
        let first_owner = std::thread::Builder::new().spawn_scoped(scope, || {
            execute(
                payload,
                cwd,
                output,
                group,
                "concurrent-preserved",
                first,
                &args[0],
                false,
                0,
            )
        });
        let second_owner = std::thread::Builder::new().spawn_scoped(scope, || {
            execute(
                payload,
                cwd,
                output,
                group,
                "concurrent-delegated",
                second,
                &args[1],
                false,
                0,
            )
        });
        let coordination = if first_owner.is_ok() && second_owner.is_ok() {
            wait_ready(&ready[0], until).and_then(|()| wait_ready(&ready[1], until))
        } else {
            Err(CiError::Message(
                "unable to start both scoped private consumers".into(),
            ))
        };
        let releases = finish
            .iter()
            .map(|path| fs::write(path, b"finish\n"))
            .collect::<Vec<_>>();
        let observed = [first_owner, second_owner]
            .into_iter()
            .map(|owner| {
                owner
                    .map_err(CiError::from)?
                    .join()
                    .map_err(|_| CiError::Message("concurrent private owner panicked".into()))?
            })
            .collect::<Vec<Result<ResultV1>>>();
        let mut errors = Vec::new();
        if let Err(error) = coordination {
            errors.push(error.to_string());
        }
        for released in releases {
            if let Err(error) = released {
                errors.push(error.to_string());
            }
        }
        for result in &observed {
            if let Err(error) = result {
                errors.push(error.to_string());
            }
        }
        if !errors.is_empty() {
            return Err(CiError::Message(errors.join("; ")));
        }
        let first = observed[0]
            .as_ref()
            .expect("all actual owners succeeded")
            .private_execution
            .as_ref()
            .expect("validated private carrier");
        let second = observed[1]
            .as_ref()
            .expect("all actual owners succeeded")
            .private_execution
            .as_ref()
            .expect("validated private carrier");
        if first.terminal.attempt_id == second.terminal.attempt_id
            || first.terminal.target_pid == second.terminal.target_pid
            || first.terminal.network_namespace == second.terminal.network_namespace
            || first.terminal.admission_metadata.admission_nonce
                == second.terminal.admission_metadata.admission_nonce
        {
            return Err(CiError::Message(
                "simultaneously live private attempts shared native boundary identities".into(),
            ));
        }
        Ok(())
    })
}

fn package_lifetime(
    payload: &MaterializedPayload,
    cwd: &Path,
    output: &Path,
    group: &str,
    registry: &RuntimePrivatePolicyRegistry,
    contracts: &[WorkloadContractV2],
) -> Result<PolicyEpoch> {
    let source_agent = binary_path(
        &payload.directory,
        "memcordon-sealed-agent",
        &payload.distribution.target,
    );
    for (contract, name) in contracts
        .iter()
        .zip(["preserved-package-live", "delegated-package-live"])
    {
        let ready = cwd.join("markers").join(name).with_extension("ready");
        let finish = cwd.join("markers").join(name).with_extension("finish");
        let arguments = [
            "gate-wait".into(),
            ready.as_os_str().to_os_string(),
            finish.as_os_str().to_os_string(),
        ];
        let until = std::time::Instant::now() + Duration::from_secs(15);
        std::thread::scope(|scope| -> Result<()> {
            let owner = std::thread::Builder::new().spawn_scoped(scope, || {
                execute(
                    payload, cwd, output, group, name, contract, &arguments, false, 0,
                )
            })?;
            let coordination = (|| -> Result<()> {
                wait_ready(&ready, until)?;
                let busy_name = if name == "preserved-package-live" {
                    "preserved-account-busy"
                } else {
                    "delegated-account-busy"
                };
                reject_launch_state(
                    payload, cwd, output, group, busy_name, CALLER, contract, true,
                )?;
                let before = sudo(
                    cwd,
                    &[
                        "cat".into(),
                        "/usr/libexec/memcordon-runtime-manifest.json".into(),
                    ],
                )?;
                for operation in ["upgrade", "uninstall"] {
                    let observed = CommandSpec::new("sudo", cwd, Duration::from_secs(30))
                        .arg("-n")
                        .arg(&source_agent)
                        .args(["package", operation])
                        .output_quiet()?;
                    let diagnostics = output.join(name);
                    fs::create_dir_all(&diagnostics)?;
                    fs::write(
                        diagnostics.join(operation).with_extension("stdout.bin"),
                        &observed.stdout,
                    )?;
                    fs::write(
                        diagnostics.join(operation).with_extension("stderr.bin"),
                        &observed.stderr,
                    )?;
                    if observed.status.success()
                        || !String::from_utf8_lossy(&observed.stderr).contains(
                            "refusing package mutation while a sealed provider attempt is active",
                        )
                    {
                        return Err(CiError::Message("active private attempt did not block package mutation before service/file changes".into()));
                    }
                }
                if before
                    != sudo(
                        cwd,
                        &[
                            "cat".into(),
                            "/usr/libexec/memcordon-runtime-manifest.json".into(),
                        ],
                    )?
                {
                    return Err(CiError::Message(
                        "refused package mutation changed installed manifest".into(),
                    ));
                }
                Ok(())
            })();
            let finish_result = fs::write(&finish, b"finish\n");
            let execution = owner
                .join()
                .map_err(|_| CiError::Message("package lifetime owner panicked".into()))?;
            let failures = [
                coordination,
                finish_result.map_err(CiError::from),
                execution.map(|_| ()),
            ]
            .into_iter()
            .filter_map(|result| result.err().map(|error| error.to_string()))
            .collect::<Vec<_>>();
            if failures.is_empty() {
                Ok(())
            } else {
                Err(CiError::Message(failures.join("; ")))
            }
        })?;
        let reuse_name = if name == "preserved-package-live" {
            "preserved-account-reused"
        } else {
            "delegated-account-reused"
        };
        execute(
            payload,
            cwd,
            output,
            group,
            reuse_name,
            contract,
            &["exit".into(), "--code".into(), "0".into()],
            false,
            0,
        )?;
    }
    let upgraded = sudo(
        &payload.directory,
        &[
            source_agent.into_os_string(),
            "package".into(),
            "upgrade".into(),
        ],
    )?;
    fs::write(output.join("idle-upgrade.stdout.bin"), upgraded)?;
    let epoch = activate(cwd, output, "after-idle-upgrade", registry)?;
    for (contract, name) in contracts
        .iter()
        .zip(["preserved-after-upgrade", "delegated-after-upgrade"])
    {
        let mut contract = contract.clone();
        contract.expected_epoch = epoch.clone();
        execute(
            payload,
            cwd,
            output,
            group,
            name,
            &contract,
            &["exit".into(), "--code".into(), "0".into()],
            false,
            0,
        )?;
    }
    Ok(epoch)
}

fn reject_launch(
    payload: &MaterializedPayload,
    cwd: &Path,
    output: &Path,
    group: &str,
    name: &str,
    caller: u32,
    contract: &WorkloadContractV2,
) -> Result<()> {
    reject_launch_state(payload, cwd, output, group, name, caller, contract, false)
}

#[expect(
    clippy::too_many_arguments,
    reason = "rejection cases retain caller inputs and expected reservation ownership independently"
)]
fn reject_launch_state(
    payload: &MaterializedPayload,
    cwd: &Path,
    output: &Path,
    group: &str,
    name: &str,
    caller: u32,
    contract: &WorkloadContractV2,
    reservation_expected: bool,
) -> Result<()> {
    reject_launch_environment(
        payload,
        cwd,
        output,
        group,
        name,
        caller,
        contract,
        reservation_expected,
        &[],
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "rejection cases retain exact hostile environment and independently expected native reservation state"
)]
fn reject_launch_environment(
    payload: &MaterializedPayload,
    cwd: &Path,
    output: &Path,
    group: &str,
    name: &str,
    caller: u32,
    contract: &WorkloadContractV2,
    reservation_expected: bool,
    environment: &[&str],
) -> Result<()> {
    let request = cwd.join(name).with_extension("request.json");
    source::write_json(&request, contract)?;
    let report_parent = cwd.join(name).with_extension("reports");
    sudo(
        cwd,
        &[
            "install".into(),
            "-d".into(),
            "-m".into(),
            "0700".into(),
            "-o".into(),
            caller.to_string().into(),
            "-g".into(),
            caller.to_string().into(),
            report_parent.as_os_str().to_os_string(),
        ],
    )?;
    let report = report_parent.join("result.json");
    let marker = cwd.join("markers").join(name);
    let mut command = CommandSpec::new("sudo", cwd, Duration::from_secs(30)).arg("-n");
    if !environment.is_empty() {
        command = command.arg("env").args(environment.iter().copied());
    }
    let observed = command
        .args([
            OsString::from("setpriv"),
            "--reuid".into(),
            caller.to_string().into(),
            "--regid".into(),
            caller.to_string().into(),
            "--groups".into(),
            group.into(),
            "--bounding-set=-all".into(),
            "--inh-caps=-all".into(),
            "--ambient-caps=-all".into(),
            "--no-new-privs".into(),
            CLI.into(),
            "--sealed".into(),
            "--workload-contract".into(),
            request.into_os_string(),
            "--report-format".into(),
            "result-v1".into(),
            "--report".into(),
            report.as_os_str().to_os_string(),
            "--".into(),
            FIXTURE.into(),
            "gate-marker".into(),
            marker.as_os_str().to_os_string(),
        ])
        .output_quiet()?;
    fs::write(
        output.join(name).with_extension("stdout.bin"),
        &observed.stdout,
    )?;
    fs::write(
        output.join(name).with_extension("stderr.bin"),
        &observed.stderr,
    )?;
    let bytes = sudo(cwd, &["cat".into(), report.into_os_string()])?;
    fs::write(output.join(name).with_extension("json"), &bytes)?;
    let result = ResultV1::parse(&bytes).map_err(CiError::Message)?;
    let rejection = result.private_rejection.as_ref().ok_or_else(|| {
        CiError::Message("preallocation denial lacks an authenticated bound rejection".into())
    })?;
    let manifest = artifacts::read_file(&payload.directory.join("runtime-manifest.json"))?;
    let provider = memcordon_core::runtime_manifest::RuntimeManifest::parse(&manifest)
        .map_err(CiError::Message)?
        .public_binding(&manifest)
        .map_err(CiError::Message)?;
    if observed.status.code() != Some(125)
        || result.outcome.wrapper_status != 125
        || result.tool.version != payload.source.version().to_string()
        || result.launch.state != memcordon_core::result_v1::LaunchStateV1::NotCreated
        || result.authorization != memcordon_core::result_v1::AuthorizationV1::RejectedBeforeRelease
        || result.outcome.kind != OutcomeKindV1::LaunchFailure
        || result.outcome.native_termination.is_some()
        || rejection.contract != *contract
        || rejection.provider != provider
        || rejection.boundary_allocated
        || rejection.reservation_may_remain != reservation_expected
        || reservation_expected && !rejection.detail.as_str().contains("MCSEALED-PRIVATE-BUSY")
        || result.cleanup.state
            != if reservation_expected {
                CleanupStateV1::Unknown
            } else {
                CleanupStateV1::Complete
            }
        || result.cleanup.direct_child_reaped
        || result.private_execution.is_some()
        || marker.try_exists()?
        || !observed.stdout.is_empty()
        || !environment.is_empty() && !rejection.detail.as_str().contains("MCSEALED-PRIVATE-ENV")
    {
        return Err(CiError::Message(
            "actual denied private launch allocated a boundary or lost its exact bound rejection"
                .into(),
        ));
    }
    Ok(())
}

fn reject_syntax(cwd: &Path, output: &Path, group: &str, name: &str, bytes: &[u8]) -> Result<()> {
    let request = cwd.join(name).with_extension("json");
    fs::write(&request, bytes)?;
    let marker = cwd.join("markers").join(name);
    let observed = CommandSpec::new("sudo", cwd, Duration::from_secs(30))
        .arg("-n")
        .args([
            OsString::from("setpriv"),
            "--reuid".into(),
            CALLER.to_string().into(),
            "--regid".into(),
            CALLER.to_string().into(),
            "--groups".into(),
            group.into(),
            "--bounding-set=-all".into(),
            "--inh-caps=-all".into(),
            "--ambient-caps=-all".into(),
            "--no-new-privs".into(),
            CLI.into(),
            "--sealed".into(),
            "--report-format".into(),
            "result-v1".into(),
            "--workload-contract".into(),
            request.into_os_string(),
            "--".into(),
            FIXTURE.into(),
            "gate-marker".into(),
            marker.as_os_str().to_os_string(),
        ])
        .output_quiet()?;
    fs::write(
        output.join(name).with_extension("stdout.bin"),
        &observed.stdout,
    )?;
    fs::write(
        output.join(name).with_extension("stderr.bin"),
        &observed.stderr,
    )?;
    let stderr = std::str::from_utf8(&observed.stderr)
        .map_err(|error| CiError::Message(error.to_string()))?;
    if observed.status.code() != Some(2)
        || !observed.stdout.is_empty()
        || !stderr
            .lines()
            .any(|line| line.starts_with("error[MCUSAGE-WORKLOAD-CONTRACT]: "))
        || marker.try_exists()?
    {
        return Err(CiError::Message(
            "installed malformed request did not reject before target allocation".into(),
        ));
    }
    Ok(())
}

fn strict_request_cases(
    cwd: &Path,
    output: &Path,
    group: &str,
    contract: &WorkloadContractV2,
) -> Result<()> {
    let valid = serde_json::to_value(contract)?;
    for (name, field, replacement) in [
        ("request-unknown-field", "unknown", serde_json::json!(true)),
        (
            "request-unknown-version",
            "schema_version",
            serde_json::json!(99),
        ),
        (
            "request-zero-epoch",
            "expected_epoch",
            serde_json::json!({"service_instance":contract.expected_epoch.service_instance,"revision":0}),
        ),
        (
            "request-unknown-identity",
            "execution_identity",
            serde_json::json!({"kind":"unknown-identity"}),
        ),
    ] {
        let mut value = valid.clone();
        value[field] = replacement;
        reject_syntax(cwd, output, group, name, &serde_json::to_vec(&value)?)?;
    }
    let mut duplicated = serde_json::to_vec(contract)?;
    if duplicated.pop() != Some(b'}') {
        return Err(CiError::Message(
            "generated request is not an object".into(),
        ));
    }
    duplicated.extend_from_slice(b",\"schema_version\":2}");
    reject_syntax(cwd, output, group, "request-duplicate-field", &duplicated)?;
    let mut oversized = serde_json::to_vec(contract)?;
    oversized.resize(memcordon_core::workload_limits::CONTRACT_BYTES + 1, b' ');
    reject_syntax(cwd, output, group, "request-oversized", &oversized)?;
    let mut ceiling = contract.clone();
    ceiling.ceiling.direct_socket_authority =
        memcordon_core::workload_contract::DirectSocketCeiling::NoNewInetSockets;
    reject_syntax(
        cwd,
        output,
        group,
        "request-profile-ceiling-mismatch",
        &serde_json::to_vec(&ceiling)?,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "advisory cases bind actual installed contract and independent positive or rejection expectation"
)]
fn advisory_case(
    payload: &MaterializedPayload,
    cwd: &Path,
    output: &Path,
    group: &str,
    name: &str,
    caller: u32,
    contract: &WorkloadContractV2,
    rejection: Option<memcordon_core::workload_registry_v2::AdmissionCodeV2>,
) -> Result<()> {
    let request = cwd.join(name).with_extension("request.json");
    source::write_json(&request, contract)?;
    let observed = CommandSpec::new("sudo", cwd, Duration::from_secs(30))
        .arg("-n")
        .args([
            OsString::from("setpriv"),
            "--reuid".into(),
            caller.to_string().into(),
            "--regid".into(),
            caller.to_string().into(),
            "--groups".into(),
            group.into(),
            "--bounding-set=-all".into(),
            "--inh-caps=-all".into(),
            "--ambient-caps=-all".into(),
            "--no-new-privs".into(),
            CLI.into(),
            "plan".into(),
            "--sealed".into(),
            "--plan-format".into(),
            "plan-v1".into(),
            "--workload-contract".into(),
            request.into_os_string(),
        ])
        .output_quiet()?;
    fs::write(
        output.join(name).with_extension("stdout.bin"),
        &observed.stdout,
    )?;
    fs::write(
        output.join(name).with_extension("stderr.bin"),
        &observed.stderr,
    )?;
    if !observed.status.success() {
        return Err(CiError::Message(
            "actual installed advisory request failed".into(),
        ));
    }
    let plan =
        memcordon_core::result_v1::PlanV1::parse(&observed.stdout).map_err(CiError::Message)?;
    let private = plan.private_plan.ok_or_else(|| {
        CiError::Message("installed advisory has no actual private provider plan".into())
    })?;
    let manifest_bytes = artifacts::read_file(&payload.directory.join("runtime-manifest.json"))?;
    let manifest = memcordon_core::runtime_manifest::RuntimeManifest::parse(&manifest_bytes)
        .map_err(CiError::Message)?;
    if plan.authorizes_launch
        || private.authorizes_launch
        || private.request != *contract
        || private.provider
            != manifest
                .public_binding(&manifest_bytes)
                .map_err(CiError::Message)?
        || private.available_for_preparation != rejection.is_none()
        || private.conflicts.as_ref().map(|value| value.code) != rejection
    {
        return Err(CiError::Message(
            "actual installed advisory request/grant/epoch/provider differs".into(),
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn endpoint_and_cancellation_cases(
    payload: &MaterializedPayload,
    cwd: &Path,
    output: &Path,
    group: &str,
    contracts: &[WorkloadContractV2],
) -> Result<()> {
    let unit = "/usr/lib/systemd/system/memcordon-sealed-network-launcher.socket";
    let backup = "/usr/lib/systemd/system/memcordon-installed-private-socket.backup";
    sudo(
        cwd,
        &["test".into(), "!".into(), "-e".into(), backup.into()],
    )?;
    let original = artifacts::read_file(Path::new(unit))?;
    sudo(
        cwd,
        &[
            "systemctl".into(),
            "stop".into(),
            "memcordon-sealed-network-launcher.socket".into(),
            "memcordon-sealed-network-launcher.service".into(),
        ],
    )?;
    let mut moved = false;
    let mutation = (|| -> Result<()> {
        for (contract, name) in contracts
            .iter()
            .zip(["preserved-endpoint-disabled", "delegated-endpoint-disabled"])
        {
            advisory_case(payload, cwd, output, group, name, CALLER, contract,
                Some(memcordon_core::workload_registry_v2::AdmissionCodeV2::HostPrerequisiteUnavailable))?;
            unavailable_launch(
                cwd,
                output,
                group,
                if name == "preserved-endpoint-disabled" {
                    "preserved-disabled-launch"
                } else {
                    "delegated-disabled-launch"
                },
                contract,
            )?;
        }
        sudo(
            cwd,
            &[
                "mv".into(),
                "--no-clobber".into(),
                unit.into(),
                backup.into(),
            ],
        )?;
        moved = true;
        sudo(cwd, &["systemctl".into(), "daemon-reload".into()])?;
        for (contract, name) in contracts
            .iter()
            .zip(["preserved-unit-missing", "delegated-unit-missing"])
        {
            advisory_case(payload, cwd, output, group, name, CALLER, contract,
                Some(memcordon_core::workload_registry_v2::AdmissionCodeV2::HostPrerequisiteUnavailable))?;
            unavailable_launch(
                cwd,
                output,
                group,
                if name == "preserved-unit-missing" {
                    "preserved-missing-unit-launch"
                } else {
                    "delegated-missing-unit-launch"
                },
                contract,
            )?;
        }
        Ok(())
    })();
    let restoration = (|| -> Result<()> {
        if moved {
            sudo(
                cwd,
                &[
                    "mv".into(),
                    "--no-clobber".into(),
                    backup.into(),
                    unit.into(),
                ],
            )?;
        }
        if artifacts::read_file(Path::new(unit))? != original {
            return Err(CiError::Message(
                "restored installed network unit differs from original bytes".into(),
            ));
        }
        sudo(cwd, &["systemctl".into(), "daemon-reload".into()])?;
        // Socket activation starts a fresh broker; RefuseManualStart forbids
        // pretending a direct manual service start is the supported path.
        sudo(
            cwd,
            &[
                "systemctl".into(),
                "start".into(),
                "memcordon-sealed-network-launcher.socket".into(),
            ],
        )?;
        Ok(())
    })();
    match (mutation, restoration) {
        (Ok(()), Ok(())) => {}
        (Err(first), Err(second)) => {
            return Err(CiError::Message(format!(
                "installed endpoint mutation: {first}; restoration: {second}"
            )));
        }
        (Err(error), _) | (_, Err(error)) => return Err(error),
    }
    for (contract, restart, cancel) in contracts
        .iter()
        .zip([
            ("preserved-service-restarted", "preserved-cancellation"),
            ("delegated-service-restarted", "delegated-cancellation"),
        ])
        .map(|(contract, (restart, cancel))| (contract, restart, cancel))
    {
        advisory_case(payload, cwd, output, group, restart, CALLER, contract, None)?;
        execute(
            payload,
            cwd,
            output,
            group,
            restart,
            contract,
            &["exit".into(), "--code".into(), "0".into()],
            false,
            0,
        )?;
        execute_controlled(
            payload,
            cwd,
            output,
            group,
            cancel,
            contract,
            &["hold".into(), "--duration".into(), "30s".into()],
            false,
            130,
            OutcomeKindV1::Interrupted,
            &[],
            true,
        )?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn unavailable_launch(
    cwd: &Path,
    output: &Path,
    group: &str,
    name: &str,
    contract: &WorkloadContractV2,
) -> Result<()> {
    let request = cwd.join(name).with_extension("request.json");
    source::write_json(&request, contract)?;
    let report = cwd.join("reports").join(name).with_extension("json");
    let marker = cwd.join("markers").join(name);
    let observed = CommandSpec::new("sudo", cwd, Duration::from_secs(45))
        .arg("-n")
        .args([
            OsString::from("setpriv"),
            "--reuid".into(),
            CALLER.to_string().into(),
            "--regid".into(),
            CALLER.to_string().into(),
            "--groups".into(),
            group.into(),
            "--bounding-set=-all".into(),
            "--inh-caps=-all".into(),
            "--ambient-caps=-all".into(),
            "--no-new-privs".into(),
            CLI.into(),
            "--sealed".into(),
            "--workload-contract".into(),
            request.into_os_string(),
            "--report-format".into(),
            "result-v1".into(),
            "--report".into(),
            report.as_os_str().to_os_string(),
            "--".into(),
            FIXTURE.into(),
            "gate-marker".into(),
            marker.as_os_str().to_os_string(),
        ])
        .output_quiet()?;
    fs::write(
        output.join(name).with_extension("stdout.bin"),
        &observed.stdout,
    )?;
    fs::write(
        output.join(name).with_extension("stderr.bin"),
        &observed.stderr,
    )?;
    let raw = sudo(cwd, &["cat".into(), report.into_os_string()])?;
    fs::write(output.join(name).with_extension("json"), &raw)?;
    let result = ResultV1::parse(&raw).map_err(CiError::Message)?;
    if observed.status.code() != Some(125)
        || result.outcome.wrapper_status != 125
        || result.launch.target_pid.is_some()
        || result.private_execution.is_some()
        || result.outcome.native_termination.is_some()
        || result.cleanup.direct_child_reaped
        || result.authorization == memcordon_core::result_v1::AuthorizationV1::Granted
        || !matches!(
            result.outcome.kind,
            OutcomeKindV1::Unknown | OutcomeKindV1::LaunchFailure
        )
        || marker.try_exists()?
        || !observed.stdout.is_empty()
    {
        return Err(CiError::Message("unavailable installed network ingress executed a target or invented native observations".into()));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn profile_and_identity_cases(
    payload: &MaterializedPayload,
    cwd: &Path,
    output: &Path,
    group: &str,
    registry: &RuntimePrivatePolicyRegistry,
    contracts: &mut [WorkloadContractV2],
) -> Result<PolicyEpoch> {
    use memcordon_core::workload_registry_v2::AdmissionCodeV2;
    for (original, foreign, plan_name, launch_name) in [
        (
            &contracts[0],
            &contracts[1],
            "preserved-foreign-identity-plan",
            "preserved-foreign-identity-launch",
        ),
        (
            &contracts[1],
            &contracts[0],
            "delegated-foreign-identity-plan",
            "delegated-foreign-identity-launch",
        ),
    ] {
        let mut changed = original.clone();
        changed.execution_identity = foreign.execution_identity.clone();
        advisory_case(
            payload,
            cwd,
            output,
            group,
            plan_name,
            CALLER,
            &changed,
            Some(AdmissionCodeV2::ExecutionIdentityNotAuthorized),
        )?;
        reject_launch(payload, cwd, output, group, launch_name, CALLER, &changed)?;
    }
    let mut disabled = registry.clone();
    disabled.profiles = bounded(disabled.profiles.as_slice().iter().cloned().map(
        |mut profile| {
            profile.enabled = false;
            profile
        },
    ))?;
    let disabled_epoch = activate(cwd, output, "disable-private-profile", &disabled)?;
    let assessment = (|| -> Result<()> {
        for (contract, (plan_name, launch_name)) in contracts.iter().zip([
            (
                "preserved-profile-disabled-plan",
                "preserved-profile-disabled-launch",
            ),
            (
                "delegated-profile-disabled-plan",
                "delegated-profile-disabled-launch",
            ),
        ]) {
            let mut changed = contract.clone();
            changed.expected_epoch = disabled_epoch.clone();
            advisory_case(
                payload,
                cwd,
                output,
                group,
                plan_name,
                CALLER,
                &changed,
                Some(AdmissionCodeV2::ProfileNotAuthorized),
            )?;
            reject_launch(payload, cwd, output, group, launch_name, CALLER, &changed)?;
        }
        Ok(())
    })();
    let restored = activate(cwd, output, "restore-private-profile", registry);
    match (assessment, restored) {
        (Ok(()), Ok(epoch)) => {
            for contract in contracts {
                contract.expected_epoch = epoch.clone();
            }
            Ok(epoch)
        }
        (Err(first), Err(second)) => Err(CiError::Message(format!(
            "disabled profile: {first}; restoration: {second}"
        ))),
        (Err(error), _) | (_, Err(error)) => Err(error),
    }
}

fn advisory_rejections(
    payload: &MaterializedPayload,
    cwd: &Path,
    output: &Path,
    group: &str,
    contract: &WorkloadContractV2,
) -> Result<()> {
    use memcordon_core::workload_registry_v2::AdmissionCodeV2 as Code;
    advisory_case(
        payload,
        cwd,
        output,
        group,
        "advisory-actual-grant",
        CALLER,
        contract,
        None,
    )?;
    advisory_case(
        payload,
        cwd,
        output,
        group,
        "advisory-wrong-caller",
        65532,
        contract,
        Some(Code::ProfileNotAuthorized),
    )?;
    reject_launch(
        payload,
        cwd,
        output,
        group,
        "launch-wrong-caller",
        65532,
        contract,
    )?;
    let mut changed = contract.clone();
    changed.authorization.grant_id = identifier("not-granted")?;
    advisory_case(
        payload,
        cwd,
        output,
        group,
        "advisory-wrong-grant",
        CALLER,
        &changed,
        Some(Code::ProfileNotAuthorized),
    )?;
    reject_launch(
        payload,
        cwd,
        output,
        group,
        "launch-wrong-grant",
        CALLER,
        &changed,
    )?;
    let mut changed = contract.clone();
    changed.authorization.grant_revision = NonZeroU64::new(
        contract
            .authorization
            .grant_revision
            .get()
            .checked_add(1)
            .ok_or_else(|| CiError::Message("grant revision exhausted".into()))?,
    )
    .expect("incremented nonzero revision");
    advisory_case(
        payload,
        cwd,
        output,
        group,
        "advisory-wrong-revision",
        CALLER,
        &changed,
        Some(Code::ProfileNotAuthorized),
    )?;
    reject_launch(
        payload,
        cwd,
        output,
        group,
        "launch-wrong-revision",
        CALLER,
        &changed,
    )?;
    let mut changed = contract.clone();
    changed.expected_epoch.revision = NonZeroU64::new(
        contract
            .expected_epoch
            .revision
            .get()
            .checked_add(1)
            .ok_or_else(|| CiError::Message("policy epoch exhausted".into()))?,
    )
    .expect("incremented nonzero revision");
    advisory_case(
        payload,
        cwd,
        output,
        group,
        "advisory-stale-epoch",
        CALLER,
        &changed,
        Some(Code::PolicyEpochStale),
    )?;
    reject_launch(
        payload,
        cwd,
        output,
        group,
        "launch-stale-epoch",
        CALLER,
        &changed,
    )?;
    let mut changed = contract.clone();
    changed.workload_plan_digest = DiagnosticSha256::from_bytes([9; 32]);
    changed.authorization.approved_plan_digest = changed.workload_plan_digest.clone();
    advisory_case(
        payload,
        cwd,
        output,
        group,
        "advisory-wrong-plan",
        CALLER,
        &changed,
        Some(Code::PlanNotApproved),
    )?;
    reject_launch(
        payload,
        cwd,
        output,
        group,
        "launch-wrong-plan",
        CALLER,
        &changed,
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
pub fn run(root: &Path, payload: &MaterializedPayload, output: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    fs::create_dir(output)?;
    let host_before = host_network_snapshot()?;
    source::write_json(&output.join("host-network-before.json"), &host_before)?;
    let work = tempfile::Builder::new()
        .prefix("memcordon-installed-private-")
        .tempdir_in("/tmp")?;
    fs::set_permissions(work.path(), fs::Permissions::from_mode(0o755))?;
    sudo(
        work.path(),
        &["test".into(), "!".into(), "-e".into(), FIXTURE.into()],
    )?;
    for path in [FIXTURE_RECEIPT, INSTALL_DEFINITION] {
        sudo(
            work.path(),
            &["test".into(), "!".into(), "-e".into(), path.into()],
        )?;
    }
    let agent = binary_path(
        &payload.directory,
        "memcordon-sealed-agent",
        &payload.distribution.target,
    );
    sudo(
        &payload.directory,
        &[agent.into_os_string(), "package".into(), "install".into()],
    )?;
    let body = (|| -> Result<()> {
        run_installed_baseline_cases(root, &output.join("baseline-native"))?;
        let registry = registry(payload)?;
        let entrypoint = registry
            .execution_identities
            .as_slice()
            .first()
            .and_then(|identity| identity.entrypoints.as_slice().first())
            .ok_or_else(|| CiError::Message("selected local fixture entrypoint absent".into()))?;
        let definition_path = work.path().join("entrypoint-install.json");
        source::write_json(
            &definition_path,
            &serde_json::json!({
                "format": "memcordon.local-entrypoint-install", "revision": 1,
                "entrypoint": entrypoint,
            }),
        )?;
        sudo(
            work.path(),
            &[
                "install".into(),
                "-m".into(),
                "0600".into(),
                "-o".into(),
                "0".into(),
                "-g".into(),
                "0".into(),
                definition_path.into_os_string(),
                INSTALL_DEFINITION.into(),
            ],
        )?;
        let installed = sudo(
            work.path(),
            &[
                AGENT.into(),
                "package".into(),
                "policy".into(),
                "entrypoint".into(),
                "install".into(),
                "--definition".into(),
                INSTALL_DEFINITION.into(),
                "--source".into(),
                payload.fixture.path.as_os_str().to_os_string(),
            ],
        )?;
        fs::write(
            output.join("actual-local-entrypoint-installation.json"),
            &installed,
        )?;
        memcordon_core::workload_contract::reject_duplicate_json_keys(&installed)
            .map_err(CiError::Message)?;
        let observed: serde_json::Value = serde_json::from_slice(&installed)
            .map_err(|error| CiError::Message(error.to_string()))?;
        let expected_entrypoint = serde_json::to_value(entrypoint)
            .map_err(|error| CiError::Message(error.to_string()))?;
        let actual = fs::symlink_metadata(FIXTURE)?;
        if observed.get("format").and_then(serde_json::Value::as_str)
            != Some("memcordon.local-entrypoint-observation")
            || observed.get("revision").and_then(serde_json::Value::as_u64) != Some(1)
            || observed.get("entrypoint") != Some(&expected_entrypoint)
            || observed
                .get("policy_activated")
                .and_then(serde_json::Value::as_bool)
                != Some(false)
            || observed.get("device").and_then(serde_json::Value::as_u64) != Some(actual.dev())
            || observed.get("inode").and_then(serde_json::Value::as_u64) != Some(actual.ino())
            || observed.get("size").and_then(serde_json::Value::as_u64) != Some(actual.len())
            || observed.get("sha256").and_then(serde_json::Value::as_str)
                != Some(payload.fixture.sha256.as_str())
            || !actual.is_file()
            || actual.uid() != 0
            || actual.mode() & 0o022 != 0
        {
            return Err(CiError::Message(
                "fresh local image observation differs from actual selected installed fixture"
                    .into(),
            ));
        }
        sudo(
            work.path(),
            &[
                "install".into(),
                "-d".into(),
                "-m".into(),
                "0700".into(),
                "-o".into(),
                CALLER.to_string().into(),
                "-g".into(),
                CALLER.to_string().into(),
                work.path().join("reports").into_os_string(),
            ],
        )?;
        let markers = work.path().join("markers");
        fs::create_dir(&markers)?;
        fs::set_permissions(&markers, fs::Permissions::from_mode(0o777))?;
        let group = sudo(
            work.path(),
            &["getent".into(), "group".into(), "memcordon".into()],
        )?;
        let group = std::str::from_utf8(&group)
            .map_err(|error| CiError::Message(error.to_string()))?
            .trim()
            .split(':')
            .nth(2)
            .ok_or_else(|| CiError::Message("installed access group has no numeric GID".into()))?;
        group
            .parse::<u32>()
            .map_err(|error| CiError::Message(error.to_string()))?;
        let registry_path = work.path().join("local-policy.json");
        source::write_json(&registry_path, &registry)?;
        let activated = sudo(
            work.path(),
            &[
                AGENT.into(),
                "package".into(),
                "policy".into(),
                "apply".into(),
                "--file".into(),
                registry_path.into_os_string(),
            ],
        )?;
        fs::write(output.join("actual-local-activation.json"), &activated)?;
        let activation: serde_json::Value = serde_json::from_slice(&activated)
            .map_err(|error| CiError::Message(error.to_string()))?;
        let mut epoch: PolicyEpoch = serde_json::from_value(
            activation
                .get("epoch")
                .cloned()
                .ok_or_else(|| CiError::Message("actual activation has no epoch".into()))?,
        )
        .map_err(|error| CiError::Message(error.to_string()))?;
        let mut contracts = Vec::new();
        for (grant, (uid, name, tcp_name, deadline_name)) in
            registry.grants.as_slice().iter().zip([
                (CALLER, "preserved", "preserved-tcp", "preserved-deadline"),
                (
                    DELEGATED,
                    "delegated",
                    "delegated-tcp",
                    "delegated-deadline",
                ),
            ])
        {
            let contract = WorkloadContractV2 {
                schema_version: ContractVersionTwo::default(),
                workload_plan_digest: grant.approved_plans.as_slice()[0].clone(),
                authorized_profile: grant.profile.clone(),
                authorization: AuthorizationRef {
                    grant_id: grant.id.clone(),
                    grant_revision: grant.revision,
                    approved_plan_digest: grant.approved_plans.as_slice()[0].clone(),
                },
                ceiling: grant.ceiling.clone(),
                requirements: BoundedVec::default(),
                endpoints: BoundedVec::default(),
                expected_epoch: epoch.clone(),
                execution_identity: grant.execution_identity.clone(),
            };
            let native = execute(
                payload,
                work.path(),
                output,
                group,
                name,
                &contract,
                &[
                    "assert-private-runtime".into(),
                    uid.to_string().into(),
                    if uid == CALLER { CALLER } else { DELEGATED }
                        .to_string()
                        .into(),
                ],
                false,
                0,
            )?;
            if uid == CALLER {
                strict_request_cases(work.path(), output, group, &contract)?;
                advisory_rejections(payload, work.path(), output, group, &contract)?;
            }
            for (name, environment) in [
                (
                    if uid == CALLER {
                        "preserved-ld-preload"
                    } else {
                        "delegated-ld-preload"
                    },
                    "LD_PRELOAD=/nonexistent/memcordon-loader-negative.so",
                ),
                (
                    if uid == CALLER {
                        "preserved-glibc-tunables"
                    } else {
                        "delegated-glibc-tunables"
                    },
                    "GLIBC_TUNABLES=glibc.malloc.check=0",
                ),
                (
                    if uid == CALLER {
                        "preserved-dyld"
                    } else {
                        "delegated-dyld"
                    },
                    "DYLD_LIBRARY_PATH=/nonexistent/memcordon-loader-negative",
                ),
            ] {
                reject_launch_environment(
                    payload,
                    work.path(),
                    output,
                    group,
                    name,
                    CALLER,
                    &contract,
                    false,
                    &[environment],
                )?;
            }
            let group_id = group
                .parse::<u32>()
                .map_err(|error| CiError::Message(error.to_string()))?;
            let expected_groups = if uid == CALLER {
                vec![group_id]
            } else {
                vec![]
            };
            let namespace_inode = validate_private_fixture(
                &artifacts::read_file(&output.join(name).with_extension("stdout.bin"))?,
                uid,
                uid,
                &expected_groups,
                fs::metadata("/proc/self/ns/net")?.ino(),
            )?;
            if native
                .private_execution
                .as_ref()
                .and_then(|execution| execution.terminal.network_namespace.as_ref())
                .is_none_or(|namespace| namespace.inode != namespace_inode)
            {
                return Err(CiError::Message(
                    "native fixture namespace differs from independently held provider namespace"
                        .into(),
                ));
            }
            let marker = markers.join(name);
            execute(
                payload,
                work.path(),
                output,
                group,
                tcp_name,
                &contract,
                &["tcp-loopback".into(), marker.as_os_str().to_os_string()],
                false,
                0,
            )?;
            if fs::read(&marker)? != b"tcp-echo-complete\n" {
                return Err(CiError::Message(
                    "native private loopback echo did not complete".into(),
                ));
            }
            execute(
                payload,
                work.path(),
                output,
                group,
                deadline_name,
                &contract,
                &["hold".into(), "--duration".into(), "10s".into()],
                true,
                123,
            )?;
            for (mode, case_name, status, policy_failure) in [
                (
                    "prebound-listener-owned",
                    if uid == CALLER {
                        "preserved-listener-owned"
                    } else {
                        "delegated-listener-owned"
                    },
                    0,
                    false,
                ),
                (
                    "prebound-listener-policy-failure",
                    if uid == CALLER {
                        "preserved-listener-policy-failure"
                    } else {
                        "delegated-listener-policy-failure"
                    },
                    42,
                    true,
                ),
            ] {
                execute(
                    payload,
                    work.path(),
                    output,
                    group,
                    case_name,
                    &contract,
                    &[mode.into()],
                    false,
                    status,
                )?;
                validate_tcp_anchor(
                    &artifacts::read_file(&output.join(case_name).with_extension("stdout.bin"))?,
                    policy_failure,
                )?;
            }
            contracts.push(contract);
        }
        for (contract, name) in contracts
            .iter()
            .zip(["preserved-lifetime", "delegated-lifetime"])
        {
            descendant_and_restart_cases(payload, work.path(), output, group, contract, name)?;
        }
        profile_and_identity_cases(
            payload,
            work.path(),
            output,
            group,
            &registry,
            &mut contracts,
        )?;
        endpoint_and_cancellation_cases(payload, work.path(), output, group, &contracts)?;
        concurrent_attempts(
            payload,
            work.path(),
            output,
            group,
            &contracts[0],
            &contracts[1],
        )?;
        epoch = package_lifetime(payload, work.path(), output, group, &registry, &contracts)?;
        for (mut contract, drain, revoke) in contracts
            .iter()
            .cloned()
            .zip([
                ("preserved-drain", "preserved-revoke"),
                ("delegated-drain", "delegated-revoke"),
            ])
            .map(|(contract, (drain, revoke))| (contract, drain, revoke))
        {
            contract.expected_epoch = epoch;
            epoch = grant_lifetime(
                payload,
                work.path(),
                output,
                group,
                &registry,
                &contract,
                drain,
                false,
            )?;
            contract.expected_epoch = epoch;
            epoch = grant_lifetime(
                payload,
                work.path(),
                output,
                group,
                &registry,
                &contract,
                revoke,
                true,
            )?;
        }
        let current_contracts = contracts
            .into_iter()
            .map(|mut contract| {
                contract.expected_epoch = epoch.clone();
                contract
            })
            .collect::<Vec<_>>();
        installed_owner_loss_cases(payload, work.path(), output, group, &current_contracts)?;
        Ok(())
    })();
    let cleanup = sudo(
        work.path(),
        &[AGENT.into(), "package".into(), "uninstall".into()],
    );
    // A failed uninstall can mean live or uncertain native ownership. Preserve
    // its protected image/creation facts rather than disposing them as proof.
    let fixture_cleanup = [FIXTURE, FIXTURE_RECEIPT, INSTALL_DEFINITION]
        .into_iter()
        .filter(|_| cleanup.is_ok())
        .map(|path| match fs::symlink_metadata(path) {
            Ok(_) => sudo(work.path(), &["unlink".into(), path.into()]).map(|_| ()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        })
        .collect::<Vec<_>>();
    let host_after = host_network_snapshot().and_then(|after| {
        source::write_json(&output.join("host-network-after.json"), &after)?;
        if after != host_before { return Err(CiError::Message("private installed execution changed host network namespace, links, routes or sysctls".into())); }
        Ok(())
    });
    let failures = [body, cleanup.map(|_| ()), host_after]
        .into_iter()
        .chain(fixture_cleanup)
        .filter_map(|result| result.err().map(|error| error.to_string()))
        .collect::<Vec<_>>();
    if failures.is_empty() {
        Ok(())
    } else {
        Err(CiError::Message(failures.join("; ")))
    }
}

/// Ordinary branch CI builds real selected binaries and Cargo sources. It
/// neither creates a release tag nor asks publication to accept working input.
pub fn run_working(root: &Path, destination: &Path) -> Result<()> {
    use super::{
        distribution::{TargetDistribution, native_target},
        packages::{self, PackageConsumer},
        source::BuildSourceIdentity,
        target,
    };
    let native = native_target()?;
    if !matches!(
        native,
        "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
    ) {
        return Err(CiError::Message(
            "private installed suite requires native GNU Linux".into(),
        ));
    }
    let source = BuildSourceIdentity::working(root)?;
    let distribution = TargetDistribution {
        target: native.into(),
        features: vec!["sealed-runtime".into(), "private-tcp".into()],
        binaries: vec!["memcordon".into(), "memcordon-sealed-agent".into()],
        units: [
            "memcordon-sealed-agent.service",
            "memcordon-sealed-agent.socket",
            "memcordon-sealed-launcher.service",
            "memcordon-sealed-launcher.socket",
            "memcordon-sealed-network-launcher.service",
            "memcordon-sealed-network-launcher.socket",
            "memcordon.conf",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect(),
    };
    distribution.validate()?;
    fs::create_dir_all(destination)?;
    let target_directory = destination.join("native-payload");
    let package_directory = destination.join("cargo-payload");
    packages::prepare_build(
        root,
        &source,
        &root.join("target/ci-build/private-packages"),
        &package_directory,
    )?;
    target::build_selected(root, &source, &distribution, &target_directory)?;
    // The extracted consumer is constructed here too, before native privileges
    // are used, so stale archives cannot bypass its exact source checks.
    let consumer = PackageConsumer::prepare(root, &package_directory)?;
    if consumer.bundle.source != source {
        return Err(CiError::Message(
            "working Cargo consumer source differs".into(),
        ));
    }
    super::installed_consumer::run(
        root,
        &target_directory,
        &package_directory,
        &destination.join("installed"),
    )?;
    run_native_observer_cases(root, &destination.join("native-observer"))?;
    source.recheck(root)
}

fn compile_native_cases(root: &Path, output: &Path) -> Result<std::path::PathBuf> {
    use cargo_metadata::Message;
    fs::create_dir(output)?;
    let compiled = crate::command::rustup_cargo(
        root,
        &crate::config::toolchains(root)?.stable,
        [
            "test",
            "--locked",
            "--release",
            "--no-run",
            "--message-format=json",
            "--package",
            "memcordon",
            "--features",
            "test-support,private-tcp",
            "--test",
            "sealed_agent",
            "--target-dir",
        ],
        Duration::from_secs(1800),
    )
    .arg(root.join("target/ci-build/private-native-tests"))
    .output_quiet()?;
    fs::write(output.join("compile.stdout.bin"), &compiled.stdout)?;
    fs::write(output.join("compile.stderr.bin"), &compiled.stderr)?;
    if !compiled.status.success() {
        return Err(CiError::Message(
            "selected native observer test compilation failed".into(),
        ));
    }
    let mut executables = Vec::new();
    for message in Message::parse_stream(compiled.stdout.as_slice()) {
        if let Message::CompilerArtifact(artifact) = message.map_err(CiError::Io)?
            && artifact.target.name == "sealed_agent"
            && artifact.profile.test
            && let Some(executable) = artifact.executable
        {
            executables.push(executable.into_std_path_buf());
        }
    }
    if executables.len() != 1 {
        return Err(CiError::Message(
            "actual native test executable is absent or ambiguous".into(),
        ));
    }
    super::target::validate_executable(
        &artifacts::read_file(&executables[0])?,
        super::distribution::native_target()?,
    )?;
    Ok(executables.remove(0))
}

#[cfg(target_os = "linux")]
fn run_installed_baseline_cases(root: &Path, output: &Path) -> Result<()> {
    fs::create_dir(output)?;
    let executable = compile_native_cases(root, &output.join("compile"))?;
    for (name, test) in [
        (
            "grant-epoch-drain-revoke",
            "native_workload_admission::native_exact_grant_epoch_and_terminal_checkpoint_are_enforced",
        ),
        (
            "tcp-baseline-denial",
            "native_workload_admission::native_tcp_requirement_preserves_baseline_authority",
        ),
    ] {
        let observed = CommandSpec::new("sudo", root, Duration::from_secs(120))
            .arg("-n")
            .arg(&executable)
            .args(["--exact", test, "--ignored", "--test-threads=1"])
            .output_quiet()?;
        fs::write(
            output.join(name).with_extension("stdout.bin"),
            &observed.stdout,
        )?;
        fs::write(
            output.join(name).with_extension("stderr.bin"),
            &observed.stderr,
        )?;
        if !observed.status.success() {
            return Err(CiError::Message(
                "selected installed baseline native case failed".into(),
            ));
        }
        crate::capability::require_exact_standard_test_success(&observed.stdout, test)?;
    }
    Ok(())
}

fn run_native_observer_cases(root: &Path, output: &Path) -> Result<()> {
    fs::create_dir(output)?;
    let executable = compile_native_cases(root, &output.join("compile"))?;
    for (name, test) in [
        (
            "image-alias",
            "native_private_image_inputs::native_private_image_install_uses_fresh_inode_despite_writable_alias",
        ),
        (
            "image-abi",
            "native_private_image_inputs::native_private_image_rejects_script_and_foreign_abi",
        ),
        (
            "image-metadata",
            "native_private_image_inputs::native_private_image_rejects_setid_filecap_and_writable_metadata",
        ),
        (
            "image-path",
            "native_private_image_inputs::native_private_image_rejects_ancestor_symlink_and_inode_substitution",
        ),
        (
            "image-bytes",
            "native_private_image_inputs::native_private_image_rejects_digest_length_and_hardlink_substitution",
        ),
        (
            "exec-stop",
            "native_descriptor_custody::native_exec_stop_precedes_first_target_instruction_and_detach_releases_it",
        ),
        (
            "trusted-exit",
            "native_descriptor_custody::native_trusted_exit_and_eof_do_not_substitute_for_exec_event",
        ),
        (
            "unexpected-stop",
            "native_descriptor_custody::native_unexpected_stop_fails_and_owned_drop_kills_then_reaps_exact_child",
        ),
        (
            "tracer-death",
            "native_descriptor_custody::native_tracer_death_exitkill_retires_trusted_child_before_exec",
        ),
        (
            "reservation-owner",
            "linux_recovery_inventory::native_account_recovery_preserves_live_owner_and_reclaims_preallocation_orphan",
        ),
        (
            "reservation-journal",
            "linux_recovery_inventory::native_account_recovery_refreshes_inventory_after_verified_allocated_journal_retirement",
        ),
        (
            "reservation-uncertainty",
            "linux_recovery_inventory::native_account_recovery_keeps_capacity_charged_for_uncertain_or_native_allocated_state",
        ),
        (
            "frontend-loss",
            "native_private_owner_loss::native_private_frontend_loss_retires_exact_guarded_cgroup",
        ),
        (
            "worker-loss",
            "native_private_owner_loss::native_private_worker_loss_retires_exact_guarded_cgroup",
        ),
        (
            "guardian-loss",
            "native_private_owner_loss::native_private_guardian_loss_never_fabricates_cgroup_retirement",
        ),
    ] {
        let observed = CommandSpec::new("sudo", root, Duration::from_secs(60))
            .arg("-n")
            .arg(&executable)
            .args(["--exact", test, "--ignored", "--test-threads=1"])
            .output_quiet()?;
        fs::write(
            output.join(name).with_extension("stdout.bin"),
            &observed.stdout,
        )?;
        fs::write(
            output.join(name).with_extension("stderr.bin"),
            &observed.stderr,
        )?;
        if !observed.status.success() {
            return Err(CiError::Message(
                "actual selected native observer case did not pass exactly once".into(),
            ));
        }
        crate::capability::require_exact_standard_test_success(&observed.stdout, test)?;
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn run(_root: &Path, _payload: &MaterializedPayload, _output: &Path) -> Result<()> {
    Err(CiError::Message(
        "Linux installed execution requires a native Linux host".into(),
    ))
}
