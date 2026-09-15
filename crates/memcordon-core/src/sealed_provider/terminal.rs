//! Pure Linux terminal receipt grammar. Parsing evidence grants no OS authority.
use sha2::{Sha256, digest::OutputSizeUser};

// These are the Linux x86_64/AArch64 wire errno values, never host errno values.
const LINUX_EPERM: i32 = 1;
const LINUX_ENOENT: i32 = 2;
const LINUX_ENOEXEC: i32 = 8;
const LINUX_EACCES: i32 = 13;
const LINUX_ENOTDIR: i32 = 20;
const LINUX_EISDIR: i32 = 21;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TerminalReceipt {
    pub policy_enforcement: crate::workload_evidence::AttemptPolicyEnforcementV1,
    pub schema_version: u32,
    pub mechanism: String,
    pub status: Option<i32>,
    pub policy_revoked: bool,
    pub exec_status: TerminalExecStatus,
    pub spawn_error_reported: bool,
    pub target_pid: u32,
    pub authorization_offset_millis: u64,
    pub assignment_verified: bool,
    pub namespaces_verified: bool,
    pub target_initial_credentials_verified: bool,
    pub initial_provider_capabilities_absent: bool,
    pub caller_envelope_digest: String,
    pub caller_no_new_privs: bool,
    pub target_no_new_privs_matched: bool,
    pub caller_capability_bounding_set_digest: String,
    pub target_capability_bounding_set_matched: bool,
    pub caller_mount_namespace_digest: String,
    pub target_mount_context_derived_from_caller: bool,
    pub credential_transition_disposition: crate::CredentialTransitionDisposition,
    pub boundary_independent_of_credentials: bool,
    pub descriptors_verified: bool,
    pub writable_ancestor_cgroup_denied: bool,
    pub parent_namespace_handles_denied: bool,
    pub recursive_provider_request_denied: bool,
    pub guardian_ready: bool,
    pub frontend_loss_authority: bool,
    pub cgroup_kill: bool,
    pub cgroup_empty: bool,
    pub init_reaped: bool,
    pub guardian_reaped: bool,
    pub boundary_retired: bool,
    pub memory_limit_exceeded: bool,
    pub deadline_exceeded: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalExecStatus {
    Succeeded,
    Failed {
        class: TerminalExecFailureClass,
        os_code: i32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TerminalExecFailureClass {
    NotFound,
    NotExecutable,
    Other,
}

pub fn parse_terminal(payload: &[u8]) -> Result<TerminalReceipt, String> {
    if payload.len() > crate::workload_limits::PUBLIC_OBJECT_BYTES {
        return Err("terminal receipt exceeds limit".into());
    }
    let text = std::str::from_utf8(payload).map_err(|_| "terminal receipt encoding".to_owned())?;
    if !payload.ends_with(b"\n") {
        return Err("terminal receipt is not newline terminated".to_owned());
    }
    let mut fields = std::collections::BTreeMap::new();
    for line in text.lines() {
        let (name, value) = line
            .split_once('=')
            .ok_or_else(|| "terminal receipt field is malformed".to_owned())?;
        if name.is_empty() || fields.insert(name, value).is_some() {
            return Err("terminal receipt contains an empty or duplicate field".to_owned());
        }
    }
    let schema_version = take_terminal_field(&mut fields, "schema-version")?
        .parse::<u32>()
        .map_err(|_| "terminal schema version invalid".to_owned())?;
    let mechanism = take_terminal_field(&mut fields, "mechanism")?.to_owned();
    let policy_bytes = take_terminal_field(&mut fields, "policy-enforcement")?.as_bytes();
    crate::workload_contract::reject_duplicate_json_keys(policy_bytes)?;
    let policy_enforcement: crate::workload_evidence::AttemptPolicyEnforcementV1 =
        serde_json::from_slice(policy_bytes).map_err(|error| error.to_string())?;
    if !policy_enforcement.is_consistent() {
        return Err("terminal policy enforcement differs".into());
    }
    if schema_version != 2 || mechanism != "linux-pid-namespace-cgroup-v2" {
        return Err("terminal receipt schema or mechanism is incompatible".to_owned());
    }
    let status = match take_terminal_field(&mut fields, "status")? {
        "none" => None,
        value => Some(
            value
                .parse()
                .map_err(|_| "terminal status invalid".to_owned())?,
        ),
    };
    let policy_revoked = match fields.remove("policy-revoked") {
        None | Some("false") => false,
        Some("true") => true,
        _ => return Err("terminal revocation flag invalid".to_owned()),
    };
    if policy_revoked != status.is_none() {
        return Err("terminal revocation and observed child status disagree".to_owned());
    }
    let exec_name = take_terminal_field(&mut fields, "exec-status")?;
    let exec_os_code = match take_terminal_field(&mut fields, "exec-os-code")? {
        "none" => None,
        value => Some(
            value
                .parse::<i32>()
                .map_err(|_| "terminal exec OS code invalid".to_owned())?,
        ),
    };
    let spawn_error_reported = take_terminal_fact(&mut fields, "spawn-error-reported")?;
    if !spawn_error_reported {
        return Err("terminal receipt omitted verified spawn-error reporting".to_owned());
    }
    let exec_status = match (exec_name, exec_os_code) {
        ("success", None) => TerminalExecStatus::Succeeded,
        ("not-found", Some(os_code)) => TerminalExecStatus::Failed {
            class: TerminalExecFailureClass::NotFound,
            os_code,
        },
        ("not-executable", Some(os_code)) => TerminalExecStatus::Failed {
            class: TerminalExecFailureClass::NotExecutable,
            os_code,
        },
        ("failed", Some(os_code)) => TerminalExecStatus::Failed {
            class: TerminalExecFailureClass::Other,
            os_code,
        },
        _ => return Err("terminal exec status and OS code are contradictory".to_owned()),
    };
    if let TerminalExecStatus::Failed { class, os_code } = exec_status {
        if os_code <= 0 || classify_terminal_exec_error(os_code) != class {
            return Err("terminal exec errno classification mismatch".to_owned());
        }
        let expected_status = match class {
            TerminalExecFailureClass::NotFound => 127,
            TerminalExecFailureClass::NotExecutable | TerminalExecFailureClass::Other => 126,
        };
        if status != Some(expected_status) {
            return Err("terminal exec failure and child status are contradictory".to_owned());
        }
    }
    let target_pid = take_terminal_field(&mut fields, "target-pid")?
        .parse()
        .map_err(|_| "terminal target pid invalid".to_owned())?;
    let authorization_offset_millis =
        take_terminal_field(&mut fields, "authorization-offset-millis")?
            .parse()
            .map_err(|_| "terminal authorization offset invalid".to_owned())?;
    let caller_envelope_digest =
        take_terminal_field(&mut fields, "caller-envelope-digest")?.to_owned();
    let caller_capability_bounding_set_digest =
        take_terminal_field(&mut fields, "caller-capability-bounding-set-digest")?.to_owned();
    let caller_mount_namespace_digest =
        take_terminal_field(&mut fields, "caller-mount-namespace-digest")?.to_owned();
    if !valid_sha256(&caller_envelope_digest)
        || !valid_sha256(&caller_capability_bounding_set_digest)
        || !valid_sha256(&caller_mount_namespace_digest)
    {
        return Err("terminal caller-envelope digest is invalid".to_owned());
    }
    let credential_transition_disposition =
        match take_terminal_field(&mut fields, "credential-transition-disposition")? {
            "preserve-caller-envelope" => {
                crate::CredentialTransitionDisposition::PreserveCallerEnvelope
            }
            _ => return Err("terminal credential-transition disposition is invalid".to_owned()),
        };
    let receipt = TerminalReceipt {
        policy_enforcement,
        schema_version,
        mechanism,
        status,
        policy_revoked,
        exec_status,
        spawn_error_reported,
        target_pid,
        authorization_offset_millis,
        assignment_verified: take_terminal_fact(&mut fields, "assignment-verified")?,
        namespaces_verified: take_terminal_fact(&mut fields, "namespaces-verified")?,
        target_initial_credentials_verified: take_terminal_fact(
            &mut fields,
            "target-initial-credentials-verified",
        )?,
        initial_provider_capabilities_absent: take_terminal_fact(
            &mut fields,
            "initial-provider-capabilities-absent",
        )?,
        caller_envelope_digest,
        caller_no_new_privs: take_terminal_fact(&mut fields, "caller-no-new-privs")?,
        target_no_new_privs_matched: take_terminal_fact(
            &mut fields,
            "target-no-new-privs-matched",
        )?,
        caller_capability_bounding_set_digest,
        target_capability_bounding_set_matched: take_terminal_fact(
            &mut fields,
            "target-capability-bounding-set-matched",
        )?,
        caller_mount_namespace_digest,
        target_mount_context_derived_from_caller: take_terminal_fact(
            &mut fields,
            "target-mount-context-derived-from-caller",
        )?,
        credential_transition_disposition,
        boundary_independent_of_credentials: take_terminal_fact(
            &mut fields,
            "boundary-independent-of-credentials",
        )?,
        descriptors_verified: take_terminal_fact(&mut fields, "descriptors-verified")?,
        writable_ancestor_cgroup_denied: take_terminal_fact(
            &mut fields,
            "writable-ancestor-cgroup-denied",
        )?,
        parent_namespace_handles_denied: take_terminal_fact(
            &mut fields,
            "parent-namespace-handles-denied",
        )?,
        recursive_provider_request_denied: take_terminal_fact(
            &mut fields,
            "recursive-provider-request-denied",
        )?,
        guardian_ready: take_terminal_fact(&mut fields, "guardian-ready-before-authorization")?,
        frontend_loss_authority: take_terminal_fact(
            &mut fields,
            "frontend-loss-authority-verified",
        )?,
        cgroup_kill: take_terminal_fact(&mut fields, "cgroup-kill-invoked")?,
        cgroup_empty: take_terminal_fact(&mut fields, "cgroup-empty")?,
        init_reaped: take_terminal_fact(&mut fields, "init-reaped")?,
        guardian_reaped: take_terminal_fact(&mut fields, "guardian-reaped")?,
        boundary_retired: take_terminal_fact(&mut fields, "boundary-retired")?,
        memory_limit_exceeded: take_terminal_fact(&mut fields, "memory-limit-exceeded")?,
        deadline_exceeded: take_terminal_fact(&mut fields, "deadline-exceeded")?,
    };
    if receipt.policy_revoked
        && (receipt.deadline_exceeded
            || !matches!(
                &receipt.policy_enforcement,
                crate::workload_evidence::AttemptPolicyEnforcementV1::Authorized {
                    terminal: crate::workload_evidence::PolicyTerminalEvidenceV1::Retired {
                        controls_preserved: true,
                        provider_resources_closed: true,
                        ..
                    },
                    ..
                }
            )
            || !receipt.cgroup_empty
            || !receipt.init_reaped
            || !receipt.guardian_reaped
            || !receipt.boundary_retired)
    {
        return Err("terminal policy revocation lacks verified admission retirement".to_owned());
    }
    if fields.is_empty() {
        Ok(receipt)
    } else {
        Err("terminal receipt contains unknown fields".to_owned())
    }
}

fn take_terminal_field<'a>(
    fields: &mut std::collections::BTreeMap<&'a str, &'a str>,
    name: &str,
) -> Result<&'a str, String> {
    fields
        .remove(name)
        .ok_or_else(|| format!("terminal field {name} missing"))
}

fn take_terminal_fact<'a>(
    fields: &mut std::collections::BTreeMap<&'a str, &'a str>,
    name: &str,
) -> Result<bool, String> {
    match take_terminal_field(fields, name)? {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(format!("terminal fact {name} invalid")),
    }
}

fn classify_terminal_exec_error(os_code: i32) -> TerminalExecFailureClass {
    match os_code {
        LINUX_ENOENT | LINUX_ENOTDIR => TerminalExecFailureClass::NotFound,
        LINUX_EACCES | LINUX_EPERM | LINUX_ENOEXEC | LINUX_EISDIR => {
            TerminalExecFailureClass::NotExecutable
        }
        _ => TerminalExecFailureClass::Other,
    }
}

fn valid_sha256(value: &str) -> bool {
    value.len() == <Sha256 as OutputSizeUser>::output_size() * 2
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
