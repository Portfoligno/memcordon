use crate::*;
use base64::Engine;
use serde::Deserializer;
use serde::de::{DeserializeOwned, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};
use std::fmt;

struct Strict(Value);
impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(decoder: D) -> Result<Self, D::Error> {
        struct StrictVisitor;
        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = Strict;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded duplicate-free JSON")
            }
            fn visit_bool<E: serde::de::Error>(self, v: bool) -> Result<Strict, E> {
                Ok(Strict(Value::Bool(v)))
            }
            fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<Strict, E> {
                Ok(Strict(Value::Number(v.into())))
            }
            fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Strict, E> {
                Ok(Strict(Value::Number(v.into())))
            }
            fn visit_f64<E: serde::de::Error>(self, _: f64) -> Result<Strict, E> {
                Err(E::custom("floating-point evidence is unsupported"))
            }
            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Strict, E> {
                if v.len() > 1024 * 1024 {
                    return Err(E::custom("JSON string exceeds bound"));
                }
                Ok(Strict(Value::String(v.to_owned())))
            }
            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Strict, E> {
                self.visit_str(&v)
            }
            fn visit_unit<E: serde::de::Error>(self) -> Result<Strict, E> {
                Ok(Strict(Value::Null))
            }
            fn visit_none<E: serde::de::Error>(self) -> Result<Strict, E> {
                self.visit_unit()
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Strict, A::Error> {
                let mut values = Vec::new();
                while let Some(Strict(v)) = access.next_element()? {
                    if values.len() >= 131_072 {
                        return Err(serde::de::Error::custom("JSON collection exceeds bound"));
                    }
                    values.push(v);
                }
                Ok(Strict(Value::Array(values)))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Strict, A::Error> {
                let mut values = Map::new();
                while let Some(key) = access.next_key::<String>()? {
                    if key.len() > 256 || values.len() >= 256 {
                        return Err(serde::de::Error::custom("JSON object exceeds bound"));
                    }
                    if values.contains_key(&key) {
                        return Err(serde::de::Error::custom("duplicate JSON key"));
                    }
                    let Strict(value) = access.next_value()?;
                    values.insert(key, value);
                }
                Ok(Strict(Value::Object(values)))
            }
        }
        decoder.deserialize_any(StrictVisitor)
    }
}

pub(crate) fn json(bytes: &[u8]) -> VerificationResult<Value> {
    if bytes.is_empty() || bytes.len() > MAX_INDEX_BYTES {
        return Err("JSON byte bound exceeded".into());
    }
    let mut decoder = serde_json::Deserializer::from_slice(bytes);
    let value = Strict::deserialize(&mut decoder).map_err(|e| e.to_string())?;
    decoder.end().map_err(|e| e.to_string())?;
    Ok(value.0)
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8]) -> VerificationResult<T> {
    serde_json::from_value(json(bytes)?).map_err(|e| e.to_string())
}

pub(crate) fn validate_arguments(args: &NativeArguments, target: &str) -> VerificationResult<()> {
    let lengths: Vec<usize> = match args {
        NativeArguments::UnixBytes(values) if target.ends_with("linux-gnu") => {
            if values.iter().any(|v| v.contains(&0)) {
                return Err("native argv contains NUL".into());
            }
            values.iter().map(Vec::len).collect()
        }
        NativeArguments::WindowsUtf16(values) if target.ends_with("windows-msvc") => {
            if values.iter().any(|v| v.contains(&0)) {
                return Err("native argv contains NUL".into());
            }
            values.iter().map(Vec::len).collect()
        }
        _ => return Err("native argv encoding differs from target".into()),
    };
    if lengths.len() > 4096
        || lengths.iter().any(|length| *length > 131_072)
        || lengths.iter().sum::<usize>() > 1024 * 1024
    {
        return Err("native argv exceeds bounds".into());
    }
    Ok(())
}

#[derive(Serialize)]
struct PublicInvocation<'a> {
    syntax: &'static str,
    budget_tokens: &'a [BudgetToken],
    memory_token: &'a Option<String>,
    deadline_token: &'a Option<String>,
    argv: Vec<PublicArgument>,
}
#[derive(Serialize)]
struct PublicArgument {
    display: String,
    raw: Option<RawArgument>,
}
#[derive(Serialize)]
struct RawArgument {
    encoding: &'static str,
    data: String,
}

pub(crate) fn invocation_digest(invocation: &NativeInvocation) -> VerificationResult<String> {
    Ok(sha256(&invocation_bytes(invocation)?))
}

fn invocation_bytes(invocation: &NativeInvocation) -> VerificationResult<Vec<u8>> {
    if invocation.budget_tokens.len() > 2 {
        return Err("invocation budget count exceeds bound".into());
    }
    let mut kinds = BTreeSet::new();
    for token in &invocation.budget_tokens {
        if !["memory", "time"].contains(&token.kind.as_str())
            || !kinds.insert(token.kind.as_str())
            || token.token.len() > 256
            || token.token.is_empty()
        {
            return Err("unknown/duplicate/invalid native budget token".into());
        }
        let selected = if token.kind == "memory" {
            &invocation.memory_token
        } else {
            &invocation.deadline_token
        };
        if selected.as_deref() != Some(token.token.as_str()) {
            return Err("budget token projection differs".into());
        }
    }
    if invocation.memory_token.is_some() != kinds.contains("memory")
        || invocation.deadline_token.is_some() != kinds.contains("time")
    {
        return Err("budget token omitted from ordered invocation".into());
    }
    let argv = match &invocation.arguments {
        NativeArguments::UnixBytes(values) => values
            .iter()
            .map(|bytes| match std::str::from_utf8(bytes) {
                Ok(text) => PublicArgument {
                    display: text.to_owned(),
                    raw: None,
                },
                Err(_) => PublicArgument {
                    display: String::from_utf8_lossy(bytes).into_owned(),
                    raw: Some(RawArgument {
                        encoding: "unix-bytes-base64",
                        data: base64::engine::general_purpose::STANDARD.encode(bytes),
                    }),
                },
            })
            .collect(),
        NativeArguments::WindowsUtf16(values) => values
            .iter()
            .map(|units| match String::from_utf16(units) {
                Ok(text) => PublicArgument {
                    display: text,
                    raw: None,
                },
                Err(_) => PublicArgument {
                    display: String::from_utf16_lossy(units),
                    raw: Some(RawArgument {
                        encoding: "windows-u16le-base64",
                        data: base64::engine::general_purpose::STANDARD.encode(
                            units
                                .iter()
                                .flat_map(|unit| unit.to_le_bytes())
                                .collect::<Vec<_>>(),
                        ),
                    }),
                },
            })
            .collect(),
    };
    let public = PublicInvocation {
        syntax: "plus-budgets-v1",
        budget_tokens: &invocation.budget_tokens,
        memory_token: &invocation.memory_token,
        deadline_token: &invocation.deadline_token,
        argv,
    };
    serde_json::to_vec(&public).map_err(|e| e.to_string())
}

fn object<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> VerificationResult<&'a Map<String, Value>> {
    let map = value.as_object().ok_or("expected JSON object")?;
    if required.iter().any(|field| !map.contains_key(*field))
        || map
            .keys()
            .any(|field| !required.contains(&field.as_str()) && !optional.contains(&field.as_str()))
    {
        return Err("missing/unknown authority-bearing wire field".into());
    }
    Ok(map)
}
fn text<'a>(value: &'a Value, field: &str) -> VerificationResult<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing string field {field}"))
}
fn number(value: &Value, field: &str) -> VerificationResult<u64> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("missing unsigned field {field}"))
}
fn yes(value: &Value, fields: &[&str]) -> VerificationResult<()> {
    if fields
        .iter()
        .any(|field| value.get(*field) != Some(&Value::Bool(true)))
    {
        return Err("native wire obligation is not true".into());
    }
    Ok(())
}
fn empty_array(value: &Value, field: &str) -> VerificationResult<()> {
    if !value
        .get(field)
        .and_then(Value::as_array)
        .is_some_and(Vec::is_empty)
    {
        return Err("wire outstanding/failure collection is not empty".into());
    }
    Ok(())
}

pub(crate) fn legacy_linux(key: &CaseKey) -> bool {
    key.family == "L-ID-01"
        && ["v1-preserve-caller", "v2-preserve-caller"].contains(&key.scenario.as_str())
}

pub(crate) fn validate_request(
    bytes: &[u8],
    key: &CaseKey,
    origin: OutcomeOrigin,
) -> VerificationResult<()> {
    let request = json(bytes);
    let intentionally_malformed = matches!(
        (key.family.as_str(), key.scenario.as_str()),
        ("L-VER-01", "unknown-request-variant" | "duplicate-request")
            | ("C-ADMISSION", "unsupported-request")
            | ("W-BINDING", "unsupported-public-request")
    );
    if intentionally_malformed {
        if origin != OutcomeOrigin::AdmissionRefusal {
            return Err("invalid request was not refused before release".into());
        }
        // Syntactic rejection or independently unknown requirement is expected;
        // a valid ordinary request cannot fill the malformed-request row.
        if let Ok(request) = request {
            let requirements = request
                .get("requirements")
                .and_then(Value::as_array)
                .ok_or("malformed request lacks required negative vector")?;
            if !requirements.iter().any(|r| {
                r.get("kind")
                    .and_then(Value::as_str)
                    .is_some_and(|k| !known_requirement(k, key.target.ends_with("linux-gnu")))
            }) {
                return Err("unsupported-request row contains no unknown variant".into());
            }
        }
        return Ok(());
    }
    let request = request?;
    let linux = key.target.ends_with("linux-gnu") && !legacy_linux(key);
    let revision = if legacy_linux(key) && key.scenario == "v2-preserve-caller" {
        2
    } else if linux {
        3
    } else {
        1
    };
    let base = [
        "schema_version",
        "workload_plan_digest",
        "authorized_profile",
        "authorization",
        "ceiling",
        "requirements",
        "expected_epoch",
    ];
    let optional = if linux {
        vec![
            "execution_identity",
            "runtime_image",
            "input_image",
            "root_layout",
            "launch",
        ]
    } else {
        vec!["endpoints", "execution_identity"]
    };
    object(&request, &base, &optional)?;
    if number(&request, "schema_version")? != revision {
        return Err("request revision differs from required case".into());
    }
    let profile = if linux {
        "linux-tcp4-unix-private-v1"
    } else if key.target.ends_with("windows-msvc") {
        "windows-host-network-external-v1"
    } else {
        "linux-tcp4-private-v1"
    };
    if request
        .pointer("/authorized_profile/id")
        .and_then(Value::as_str)
        != Some(profile)
        && origin != OutcomeOrigin::AdmissionRefusal
    {
        return Err("request profile differs".into());
    }
    digest(text(&request, "workload_plan_digest")?)?;
    if request.get("workload_plan_digest") != request.pointer("/authorization/approved_plan_digest")
        && origin != OutcomeOrigin::AdmissionRefusal
    {
        return Err("request plan/authorization differs".into());
    }
    let requirements = request
        .get("requirements")
        .and_then(Value::as_array)
        .ok_or("request requirements missing")?;
    let closure_only = linux
        && ((key.family == "L-LIFE-02"
            && key.scenario.split_once('-').is_some_and(|(actor, phase)| {
                ["frontend", "worker", "guardian", "control"].contains(&actor)
                    && ["allocation", "release", "drain"].contains(&phase)
            }))
            || (key.family == "L-LIFE-05" && key.scenario == "report-persistence-failure")
            || (key.family == "L-LIFE-05" && key.scenario == "relay-backpressure")
            || (key.family == "C-STATUS"
                && ["deadline", "memory"].contains(&key.scenario.as_str()))
            || (["C-IO", "L-MIX-05"].contains(&key.family.as_str())
                && key.scenario == "bounded-large-output")
            || (key.family == "L-ISO-04"
                && [
                    "symlink",
                    "dotdot",
                    "proc-root",
                    "proc-cwd",
                    "proc-fd",
                    "hardlink",
                    "opath",
                    "mount-alias",
                ]
                .contains(&key.scenario.as_str()))
            || (key.family == "L-IMG-04"
                && [
                    "export-symlink",
                    "export-fifo",
                    "export-device",
                    "export-traversal",
                    "export-concurrent-writer",
                ]
                .contains(&key.scenario.as_str())));
    if requirements.is_empty() && !closure_only || requirements.len() > 64 {
        return Err("request requirement cardinality differs".into());
    }
    let mut ids = BTreeSet::new();
    for requirement in requirements {
        let kind = text(requirement, "kind")?;
        if !known_requirement(kind, linux) {
            return Err("unknown authority-bearing request variant".into());
        }
        if !ids.insert(text(requirement, "id")?) {
            return Err("duplicate request requirement identity".into());
        }
    }
    if linux
        && [
            "execution_identity",
            "runtime_image",
            "input_image",
            "root_layout",
            "launch",
        ]
        .iter()
        .any(|field| request.get(*field).is_none_or(Value::is_null))
    {
        return Err("V3 immutable root/identity bindings omitted".into());
    }
    Ok(())
}

fn known_requirement(kind: &str, linux: bool) -> bool {
    if linux {
        [
            "tcp_listener",
            "unix_stream_pair",
            "unix_path_stream",
            "unix_abstract_stream",
            "intra_attempt_descriptor_transfer",
            "generated_executable",
            "expected_denial",
        ]
        .contains(&kind)
    } else {
        [
            "unix-socket-creation",
            "unix-socket-pair",
            "tcp",
            "supplied-tcp-listener",
            "denial-exercise",
        ]
        .contains(&kind)
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "Keep result bytes, public request, native observation and custody as independent comparison inputs"
)]
pub(crate) fn validate_result(
    bytes: &[u8],
    terminal: Option<&[u8]>,
    request: &[u8],
    native: &NativeObservation,
    key: &CaseKey,
    version: &str,
    source: &str,
    evidence: &CaseEvidence,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let result = json(bytes)?;
    if key.target.ends_with("windows-msvc")
        && key.family == "W-IO"
        && key.scenario == "argv-nul-rejection"
    {
        validate_windows_argument_refusal(&result, native)?;
        if terminal.is_some() {
            return Err("NUL facade refusal invents authenticated terminal".into());
        }
        return Ok(());
    }
    if key.target.ends_with("linux-gnu") && !legacy_linux(key) {
        return validate_linux_v2(
            &result, request, native, key, version, source, evidence, custody,
        );
    }
    let fields = [
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
    ];
    let revision = if key.target.ends_with("linux-gnu") && !legacy_linux(key) {
        2
    } else {
        1
    };
    object(&result, &fields, &[])?;
    if text(&result, "format")? != "memcordon.result" || number(&result, "revision")? != revision {
        return Err("raw result format/revision differs".into());
    }
    let tool = result.get("tool").ok_or("tool missing")?;
    object(
        tool,
        &["name", "version", "os", "architecture", "runtime_features"],
        &[],
    )?;
    if text(tool, "name")? != "memcordon"
        || text(tool, "version")? != version
        || text(tool, "architecture")? != key.target.split('-').next().ok_or("invalid target")?
    {
        return Err("raw result tool identity differs".into());
    }
    if result
        .pointer("/invocation/association_sha256")
        .and_then(Value::as_str)
        != Some(native.invocation_sha256.as_str())
    {
        return Err("raw result native invocation association differs".into());
    }
    let cleanup = result.get("cleanup").ok_or("cleanup missing")?;
    object(
        cleanup,
        &[
            "state",
            "direct_child_reaped",
            "workload_empty",
            "outstanding",
            "failed_operations",
        ],
        &[],
    )?;
    if text(cleanup, "state")? != "complete" {
        return Err("raw result cleanup uncertain/incomplete".into());
    }
    empty_array(cleanup, "outstanding")?;
    empty_array(cleanup, "failed_operations")?;
    let launch = result.get("launch").ok_or("launch missing")?;
    object(launch, &["state", "target_pid"], &[])?;
    let outcome = result.get("outcome").ok_or("outcome missing")?;
    object(
        outcome,
        &["kind", "native_termination", "wrapper_status"],
        &[],
    )?;
    if outcome.get("wrapper_status").and_then(Value::as_i64)
        != Some(i64::from(native.frontend_status))
    {
        return Err("raw result/frontend native status differs".into());
    }
    let expected = match native.origin {
        OutcomeOrigin::Target | OutcomeOrigin::ApplicationRefusal => "completed",
        OutcomeOrigin::Deadline => "deadline",
        OutcomeOrigin::Memory => "confirmed-memory-limit",
        OutcomeOrigin::Interrupted => "interrupted",
        OutcomeOrigin::ProviderFailure => "provider-failure",
        OutcomeOrigin::AdmissionRefusal => "provider-failure",
        _ => return Err("nonexecution origin cannot supply public result".into()),
    };
    if text(outcome, "kind")? != expected {
        return Err("raw result cause differs from independent native origin".into());
    }
    if native.origin == OutcomeOrigin::AdmissionRefusal {
        if text(&result, "authorization")? != "rejected-before-release"
            || !["not-created", "gated-unreleased"].contains(&text(launch, "state")?)
            || native.root_pid.is_some()
        {
            return Err("admission refusal released a target or misstates authority".into());
        }
        return Ok(());
    }
    if text(&result, "authorization")? != "granted"
        || launch.get("target_pid").and_then(Value::as_u64) != native.root_pid.map(u64::from)
    {
        return Err("public launch/authenticated native target differs".into());
    }
    yes(cleanup, &["direct_child_reaped", "workload_empty"])?;
    if native.origin == OutcomeOrigin::Target || native.origin == OutcomeOrigin::ApplicationRefusal
    {
        let termination = outcome
            .get("native_termination")
            .ok_or("native target termination missing")?;
        let status = native.target_status.ok_or("native target status missing")?;
        match text(termination, "kind")? {
            "exit-code" => {
                object(termination, &["kind", "code"], &[])?;
                if termination.get("code").and_then(Value::as_i64) != Some(i64::from(status)) {
                    return Err("target exit status differs".into());
                }
            }
            "windows-status" => {
                object(termination, &["kind", "status"], &[])?;
                if number(termination, "status")? != u64::from(status as u32) {
                    return Err("Windows target status differs".into());
                }
            }
            _ => return Err("successful target case has unknown/nonexit termination".into()),
        }
    }
    let association = result
        .get("provider_association")
        .ok_or("provider association missing")?;
    object(
        association,
        &["provider", "attempt_id", "request_sha256"],
        &[],
    )?;
    if association.get("attempt_id").and_then(Value::as_str) != native.attempt_id.as_deref()
        || association.get("request_sha256").and_then(Value::as_str)
            != native.request_sha256.as_deref()
    {
        return Err("raw result native attempt/request differs".into());
    }
    if key.target.ends_with("windows-msvc") {
        let terminal = terminal.ok_or("Windows case omits captured authenticated terminal")?;
        validate_windows_runtime(&result, terminal, native, key)?;
        let actual_request = custody.bytes(
            evidence
                .provider_request
                .as_deref()
                .ok_or("Windows actual provider request missing")?,
        )?;
        let sidecar = json(terminal)?;
        if provider_request_bytes(&sidecar)? != actual_request {
            return Err("sidecar/collected actual provider request differs".into());
        }
        let invocation: NativeInvocation = decode(custody.bytes(&evidence.invocation)?)?;
        validate_windows_request(
            actual_request,
            request,
            &invocation,
            custody.bytes(&invocation.environment)?,
        )?;
    } else {
        let runtime = result
            .get("runtime")
            .ok_or("legacy Linux runtime missing")?;
        if text(runtime, "kind")? != "linux-private-tcp4" {
            return Err("legacy regression omitted native private runtime".into());
        }
        yes(
            runtime,
            &[
                "private_namespace_observed",
                "no_socket_at_entry",
                "exec_observed",
                "resources_retired",
            ],
        )?;
    }
    Ok(())
}

pub(crate) fn validate_windows_argument_refusal(
    result: &Value,
    native: &NativeObservation,
) -> VerificationResult<()> {
    object(
        result,
        &[
            "format",
            "revision",
            "argument_utf16",
            "code",
            "category",
            "target_pid",
            "target_released",
            "provider_association",
            "detail",
        ],
        &[],
    )?;
    if text(result, "format")? != "memcordon.windows-native-argv-refusal"
        || number(result, "revision")? != 1
        || result.get("argument_utf16") != Some(&serde_json::json!([97, 0, 98]))
        || text(result, "code")? != "MCSEALED-WINDOWS-REQUEST"
        || text(result, "category")? != "Usage"
        || result.get("target_pid") != Some(&Value::Null)
        || result.get("target_released") != Some(&Value::Bool(false))
        || result.get("provider_association") != Some(&Value::Null)
        || text(result, "detail")?.is_empty()
        || native.origin != OutcomeOrigin::AdmissionRefusal
        || native.root_pid.is_some()
        || native.target_status.is_some()
    {
        return Err("native facade NUL refusal differs or invents authorization".into());
    }
    Ok(())
}

pub(crate) fn validate_windows_loss(
    evidence: &CaseEvidence,
    native: &NativeObservation,
    key: &CaseKey,
    product: &ProductObservation,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let allowed = key.target.ends_with("windows-msvc")
        && ((key.family == "W-RETIREMENT"
            && [
                "frontend-loss",
                "control-service-loss",
                "attempt-worker-loss",
            ]
            .contains(&key.scenario.as_str()))
            || (key.family == "C-LIFETIME"
                && ["frontend-loss", "service-loss", "worker-loss"]
                    .contains(&key.scenario.as_str())));
    if !allowed || native.origin != OutcomeOrigin::ProviderFailure {
        return Err("external loss substituted into another row/origin".into());
    }
    let loss = evidence
        .windows_loss
        .as_ref()
        .ok_or("external loss artifact crosswalk absent")?;
    custody.bytes(&loss.stdout)?;
    custody.bytes(&loss.stderr)?;
    if let Some(path) = &loss.capture_failure
        && custody.bytes(path)?.is_empty()
    {
        return Err("empty loss capture failure".into());
    }
    let action = json(custody.bytes(&loss.action)?)?;
    object(
        &action,
        &[
            "format",
            "revision",
            "kind",
            "process",
            "thread",
            "native_requested_status",
            "subject_role",
            "image_sha256",
            "subject_held_before_action",
            "action_completed",
        ],
        &["control_service"],
    )?;
    if text(&action, "format")? != "memcordon.windows-native-loss-action"
        || number(&action, "revision")? != 1
        || number(&action, "native_requested_status")? != 126
    {
        return Err("native loss action format/status differs".into());
    }
    yes(&action, &["subject_held_before_action", "action_completed"])?;
    let worker = ["attempt-worker-loss", "worker-loss"].contains(&key.scenario.as_str());
    let frontend = key.scenario == "frontend-loss";
    let role = if worker {
        "attempt-worker"
    } else if frontend {
        "frontend"
    } else {
        "control-service"
    };
    if text(&action, "subject_role")? != role
        || text(&action, "kind")?
            != if worker {
                "terminate-thread"
            } else {
                "terminate-process"
            }
    {
        return Err("native loss subject/action differs".into());
    }
    let selected = product
        .components
        .iter()
        .find(|c| {
            c.role
                == if frontend {
                    "public-cli"
                } else {
                    "sealed-agent"
                }
        })
        .ok_or("loss subject selected image missing")?;
    if text(&action, "image_sha256")? != selected.installed_sha256 {
        return Err("fault subject image differs from installed selection".into());
    }
    let process = action
        .get("process")
        .ok_or("fault subject identity absent")?;
    object(process, &["process_id", "creation_time_100ns"], &[])?;
    if number(process, "process_id")? == 0
        || number(process, "creation_time_100ns")? == 0
        || process.get("process_id").and_then(Value::as_u64) == native.root_pid.map(u64::from)
    {
        return Err("fault subject identity absent or target substituted".into());
    }
    if !worker && !frontend {
        let scm = action
            .get("control_service")
            .ok_or("control service native SCM observation absent")?;
        object(scm, &["name", "process_id", "current_state"], &[])?;
        if text(scm, "name")? != "MemCordonSealedControl"
            || scm.get("process_id") != process.get("process_id")
            || number(scm, "current_state")? != 4
        {
            return Err("control service fault acted on another/nonrunning SCM process".into());
        }
    } else if action.get("control_service").is_some() {
        return Err("nonservice loss invented SCM authority".into());
    }
    let family = json(custody.bytes(&loss.native_family_retirement)?)?;
    object(
        &family,
        &[
            "format",
            "revision",
            "attempt_id",
            "nonce",
            "request_sha256",
            "root_pid",
            "root_birth",
            "processes",
        ],
        &[],
    )?;
    if text(&family, "format")? != "memcordon.windows-native-family-retirement"
        || number(&family, "revision")? != 1
        || family.get("attempt_id").and_then(Value::as_str) != native.attempt_id.as_deref()
        || family.get("nonce").and_then(Value::as_str) != native.attempt_nonce.as_deref()
        || family.get("request_sha256").and_then(Value::as_str) != native.request_sha256.as_deref()
        || family.get("root_pid").and_then(Value::as_u64) != native.root_pid.map(u64::from)
        || family.get("root_birth").and_then(Value::as_u64) != native.root_birth
    {
        return Err("native loss held-family raw association differs".into());
    }
    let processes = family
        .get("processes")
        .and_then(Value::as_array)
        .ok_or("native loss family members absent")?;
    if processes.len() != 2 || native.held_processes.len() != 2 {
        return Err("native loss requires independently held root and descendant".into());
    }
    let mut members = BTreeSet::new();
    for member in processes {
        object(
            member,
            &[
                "pid",
                "birth",
                "parent_pid",
                "parent_birth",
                "held_before_action",
                "retirement_observed",
            ],
            &[],
        )?;
        yes(member, &["held_before_action", "retirement_observed"])?;
        let pid =
            u32::try_from(number(member, "pid")?).map_err(|_| "native loss PID outside bound")?;
        let birth = number(member, "birth")?;
        if pid == 0 || birth == 0 || !members.insert((pid, birth)) {
            return Err("native loss family identity missing/duplicated".into());
        }
        let expected = native
            .held_processes
            .iter()
            .find(|held| (held.pid, held.birth) == (pid, birth))
            .ok_or("native loss raw member not independently held")?;
        if !expected.retirement_observed
            || member.get("parent_pid")
                != Some(&serde_json::to_value(expected.parent_pid).map_err(|e| e.to_string())?)
            || member.get("parent_birth")
                != Some(&serde_json::to_value(expected.parent_birth).map_err(|e| e.to_string())?)
        {
            return Err("native loss member parent/retirement differs".into());
        }
        if Some(pid) == native.root_pid {
            if expected.parent_pid.is_some() || expected.parent_birth.is_some() {
                return Err("native loss root invents parent authority".into());
            }
        } else if expected.parent_pid != native.root_pid
            || expected.parent_birth != native.root_birth
            || native.root_birth.is_none_or(|root| root > birth)
        {
            return Err("native loss descendant ancestry/birth differs".into());
        }
    }
    let live = json(custody.bytes(&loss.live_observation)?)?;
    object(
        &live,
        &[
            "format",
            "revision",
            "challenge",
            "guardian_identity",
            "association",
        ],
        &[
            "live_nonce",
            "live_target_identity",
            "worker_process_identity",
            "worker_thread_identity",
        ],
    )?;
    let semantic: SemanticObservation = decode(custody.bytes(&evidence.semantic_observation)?)?;
    if text(&live, "format")? != "memcordon.windows-live-guardian-observation"
        || number(&live, "revision")? != 1
        || text(&live, "challenge")? != hex::encode(custody.bytes(&semantic.challenge)?)
    {
        return Err("live loss observation revision/challenge differs".into());
    }
    for field in [
        "guardian_identity",
        "live_target_identity",
        "worker_process_identity",
    ] {
        if let Some(identity) = live.get(field).filter(|value| !value.is_null()) {
            object(identity, &["process_id", "creation_time_100ns"], &[])?;
            if number(identity, "process_id")? == 0 || number(identity, "creation_time_100ns")? == 0
            {
                return Err("live fault native process identity absent".into());
            }
        }
    }
    let association = live
        .get("association")
        .ok_or("live loss association absent")?;
    object(
        association,
        &["provider", "attempt_id", "request_sha256"],
        &[],
    )?;
    let provider = association.get("provider").ok_or("live provider absent")?;
    object(
        provider,
        &["generation", "source_commit", "runtime_manifest_sha256"],
        &[],
    )?;
    if provider.get("generation").and_then(Value::as_str) != native.provider_generation.as_deref()
        || provider.get("source_commit").and_then(Value::as_str)
            != Some(product.source_commit.as_str())
        || provider
            .get("runtime_manifest_sha256")
            .and_then(Value::as_str)
            != native.runtime_manifest_sha256.as_deref()
    {
        return Err("live loss provider differs from installed selection".into());
    }
    if association.get("attempt_id").and_then(Value::as_str) != native.attempt_id.as_deref()
        || association.get("request_sha256").and_then(Value::as_str)
            != native.request_sha256.as_deref()
        || live.get("live_nonce").and_then(Value::as_str) != native.attempt_nonce.as_deref()
        || live
            .pointer("/live_target_identity/process_id")
            .and_then(Value::as_u64)
            != native.root_pid.map(u64::from)
        || live
            .pointer("/live_target_identity/creation_time_100ns")
            .and_then(Value::as_u64)
            != native.root_birth
    {
        return Err("live fault root/transaction differs from held native identity".into());
    }
    if worker {
        if live.get("worker_process_identity") != Some(process)
            || live.get("worker_thread_identity") != action.get("thread")
            || action.get("thread").is_none_or(Value::is_null)
        {
            return Err("native worker fault did not act on exact live worker".into());
        }
        let thread = action.get("thread").ok_or("native worker thread absent")?;
        object(thread, &["thread_id", "creation_time_100ns"], &[])?;
        if number(thread, "thread_id")? == 0 || number(thread, "creation_time_100ns")? == 0 {
            return Err("native fault worker thread identity absent".into());
        }
    } else if !action.get("thread").is_none_or(Value::is_null) {
        return Err("process loss invented worker thread".into());
    }
    let provider_request = custody.bytes(
        evidence
            .provider_request
            .as_deref()
            .ok_or("loss actual prelaunch request absent")?,
    )?;
    if native.request_sha256.as_deref() != Some(sha256(provider_request).as_str()) {
        return Err("loss actual request bytes differ from authenticated association".into());
    }
    let invocation: NativeInvocation = decode(custody.bytes(&evidence.invocation)?)?;
    validate_windows_request(
        provider_request,
        custody.bytes(
            evidence
                .request
                .as_deref()
                .ok_or("loss requested contract absent")?,
        )?,
        &invocation,
        custody.bytes(&invocation.environment)?,
    )?;
    let actual_request = json(provider_request)?;
    if actual_request.get("expected_provider_binding") != Some(provider)
        || actual_request.get("nonce") != live.get("live_nonce")
    {
        return Err("loss actual request differs from live provider/nonce".into());
    }
    if let Some(path) = &loss.original_result {
        let original = json(custody.bytes(path)?)?;
        object(
            &original,
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
            &[],
        )?;
        if text(&original, "format")? != "memcordon.result"
            || number(&original, "revision")? != 1
            || original.get("provider_association") != Some(association)
            || original.pointer("/outcome/kind").and_then(Value::as_str) != Some("provider-failure")
        {
            return Err(
                "loss original result substituted completed/different cause or association".into(),
            );
        }
        let outcome = original.get("outcome").ok_or("original outcome absent")?;
        object(
            outcome,
            &["kind", "native_termination", "wrapper_status"],
            &[],
        )?;
        let runtime = original.get("runtime").ok_or("original runtime absent")?;
        match text(runtime, "kind")? {
            "windows-sealed" => {
                object(runtime, &["kind", "observation"], &[])?;
            }
            "unavailable" => {
                object(runtime, &["kind", "reason"], &[])?;
                if text(runtime, "reason")?.is_empty() {
                    return Err("original unavailable runtime reason absent".into());
                }
            }
            _ => return Err("original loss runtime has unknown/wrong authority variant".into()),
        }
        if let Some(diagnostic) = original.get("diagnostics").filter(|value| !value.is_null()) {
            object(
                diagnostic,
                &[
                    "schema_version",
                    "provider_binding",
                    "attempt_id",
                    "request_sha256",
                    "diagnostic_sequence",
                    "durable_through_sequence",
                    "original",
                    "secondary",
                    "loss",
                    "projection_sha256",
                ],
                &[],
            )?;
            if number(diagnostic, "schema_version")? != 1
                || diagnostic.get("provider_binding") != Some(provider)
                || diagnostic.get("attempt_id") != association.get("attempt_id")
                || diagnostic.get("request_sha256") != association.get("request_sha256")
            {
                return Err("original diagnostic binding/revision differs".into());
            }
            digest(text(diagnostic, "projection_sha256")?)?;
            validate_original_failure(
                diagnostic
                    .get("original")
                    .ok_or("original diagnostic cause absent")?,
            )?;
        }
    }
    let recovery = json(custody.bytes(&loss.recovery)?)?;
    let owner = json(custody.bytes(&loss.original_lease_owner)?)?;
    let deadlines = json(custody.bytes(&loss.original_deadlines)?)?;
    object(
        &owner,
        &[
            "format",
            "revision",
            "identity",
            "key",
            "current",
            "predecessor",
            "binary_root",
            "state_root",
            "policy_root",
            "artifact_root",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
        &[],
    )?;
    object(
        &deadlines,
        &[
            "format",
            "revision",
            "identity",
            "key",
            "artifact_root",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
        &[],
    )?;
    object(
        &owner["identity"],
        &["run_id", "source_commit", "source_tree_sha256", "version"],
        &[],
    )?;
    object(&owner["key"], &["target", "channel"], &[])?;
    if owner["format"] != "memcordon.consumer-readiness.windows-lease-owner"
        || owner["revision"] != 1
        || deadlines["format"] != "memcordon.consumer-readiness.windows-original-deadlines"
        || deadlines["revision"] != 1
        || owner["identity"] != deadlines["identity"]
        || owner["key"] != serde_json::to_value(&product.key).map_err(|e| e.to_string())?
        || owner["key"] != deadlines["key"]
        || owner["artifact_root"] != deadlines["artifact_root"]
        || owner["identity"]["run_id"] != evidence.run_id
        || owner["identity"]["source_commit"] != evidence.source_commit
        || owner["identity"]["source_tree_sha256"] != evidence.source_tree_sha256
        || owner["identity"]["version"] != product.version
    {
        return Err("loss recovery original installation owner/deadline source differs".into());
    }
    let work = number(&deadlines, "work_deadline_unix_millis")?;
    let cleanup = number(&deadlines, "cleanup_deadline_unix_millis")?;
    if work == 0
        || cleanup.checked_sub(work) != Some(15 * 60 * 1000)
        || owner["work_deadline_unix_millis"] != work
        || owner["cleanup_deadline_unix_millis"] != cleanup
    {
        return Err("loss recovery renewed original work/cleanup cutoffs".into());
    }
    let current = &owner["current"];
    object(
        current,
        &[
            "channel",
            "source_commit",
            "version",
            "target",
            "artifacts",
            "cli",
            "agent",
            "components",
            "installed_components",
            "fixture",
            "installed_agent",
            "installed_manifest",
            "provider",
            "output_directory",
        ],
        &[],
    )?;
    let cli = product
        .components
        .iter()
        .find(|component| component.role == "public-cli")
        .ok_or("loss recovery original CLI selection absent")?;
    object(&current["cli"], &["path", "sha256"], &[])?;
    let native_path = |value: &Value| -> VerificationResult<String> {
        let path = value.as_str().ok_or("loss original native path absent")?;
        if path.len() < 3
            || !path.as_bytes()[0].is_ascii_alphabetic()
            || path.as_bytes()[1] != b':'
            || path[2..].contains(':')
            || !matches!(path.as_bytes()[2], b'\\' | b'/')
            || path.contains('\0')
            || path
                .split(['\\', '/'])
                .any(|component| matches!(component, "." | ".."))
        {
            return Err("loss original native path malformed/escaping".into());
        }
        Ok(path.to_owned())
    };
    let artifact_root = native_path(&owner["artifact_root"])?;
    for path in [&current["output_directory"], &current["cli"]["path"]] {
        let path = native_path(path)?;
        if path
            .strip_prefix(artifact_root.trim_end_matches(['\\', '/']))
            .is_none_or(|suffix| !suffix.starts_with(['\\', '/']))
        {
            return Err(
                "loss original selected recovery command escapes original artifact lifetime".into(),
            );
        }
    }
    let installed_channel = match key.channel.as_deref() {
        Some("candidate-native" | "public-native") => "native-bundle",
        Some("candidate-cargo" | "public-cargo") => "cargo-package",
        _ => return Err("loss original installed channel absent/unknown".into()),
    };
    if current["source_commit"] != evidence.source_commit
        || current["version"] != product.version
        || current["target"] != key.target
        || current["channel"] != installed_channel
        || current["provider"] != *provider
        || current["cli"]["sha256"] != cli.installed_sha256
    {
        return Err("loss recovery selected original CLI/provider differs".into());
    }
    let command_bytes = custody.bytes(&loss.recovery_invocation)?;
    let command = json(command_bytes)?;
    object(
        &command,
        &[
            "format",
            "revision",
            "target",
            "source_commit",
            "executable_sha256",
            "program_utf16",
            "argv_utf16",
            "cwd_utf16",
            "environment_cleared",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
            "started_unix_millis",
            "budget_millis",
            "recovery_deadline_unix_millis",
        ],
        &[],
    )?;
    let started = number(&command, "started_unix_millis")?;
    let budget = number(&command, "budget_millis")?;
    let recovery_cutoff = number(&command, "recovery_deadline_unix_millis")?;
    if started == 0
        || budget == 0
        || budget > 10000
        || recovery_cutoff > cleanup
        || recovery_cutoff
            .checked_sub(started)
            .is_none_or(|remaining| remaining > 90000 || budget > remaining)
    {
        return Err("loss recovery original command starts after cleanup or extends bounded original cutoff".into());
    }
    let utf16 = |value: &Value| -> VerificationResult<Vec<u16>> {
        serde_json::from_value(value.clone())
            .map_err(|_| "loss recovery native UTF16 operands malformed".into())
    };
    let expected_argv = [
        "windows-recover",
        "attempt",
        native
            .attempt_id
            .as_deref()
            .ok_or("loss original attempt absent")?,
        native
            .attempt_nonce
            .as_deref()
            .ok_or("loss original nonce absent")?,
        native
            .request_sha256
            .as_deref()
            .ok_or("loss original request absent")?,
    ]
    .map(|arg| arg.encode_utf16().collect::<Vec<_>>());
    let argv: Vec<Vec<u16>> = serde_json::from_value(command["argv_utf16"].clone())
        .map_err(|_| "loss recovery argv malformed")?;
    if command["format"] != "memcordon.windows-loss-recovery-command"
        || command["revision"] != 1
        || command["target"] != key.target
        || command["source_commit"] != evidence.source_commit
        || command["executable_sha256"] != cli.installed_sha256
        || command["environment_cleared"] != true
        || command["work_deadline_unix_millis"] != work
        || command["cleanup_deadline_unix_millis"] != cleanup
        || argv != expected_argv
        || utf16(&command["program_utf16"])?
            != text(&current["cli"], "path")?
                .encode_utf16()
                .collect::<Vec<_>>()
        || utf16(&command["cwd_utf16"])?
            != text(current, "output_directory")?
                .encode_utf16()
                .collect::<Vec<_>>()
    {
        return Err(
            "loss recovery command reassociated operands/image/native cwd or renewed cutoffs"
                .into(),
        );
    }
    let creation = json(custody.bytes(&loss.recovery_creation)?)?;
    let process = json(custody.bytes(&loss.recovery_process)?)?;
    object(
        &creation,
        &[
            "format",
            "revision",
            "invocation_sha256",
            "process",
            "image_sha256",
            "creation_handle_retained",
        ],
        &[],
    )?;
    object(
        &process,
        &[
            "format",
            "revision",
            "invocation_sha256",
            "process",
            "image_sha256",
            "native_status",
            "native_wait_completed",
            "capture_complete",
            "stdout_sha256",
            "stderr_sha256",
        ],
        &[],
    )?;
    object(
        &creation["process"],
        &["process_id", "creation_time_100ns"],
        &[],
    )?;
    if creation["format"] != "memcordon.windows-loss-recovery-creation"
        || process["format"] != "memcordon.windows-loss-recovery-process"
        || creation["revision"] != 1
        || process["revision"] != 1
        || creation["process"] != process["process"]
        || number(&creation["process"], "process_id")? == 0
        || number(&creation["process"], "process_id")? > u32::MAX as u64
        || number(&creation["process"], "creation_time_100ns")? == 0
        || creation["creation_handle_retained"] != true
        || creation["invocation_sha256"] != sha256(command_bytes)
        || process["invocation_sha256"] != sha256(command_bytes)
        || creation["image_sha256"] != cli.installed_sha256
        || process["image_sha256"] != cli.installed_sha256
        || process["native_status"] != 0
        || process["native_wait_completed"] != true
        || process["capture_complete"] != true
        || process["stdout_sha256"] != sha256(custody.bytes(&loss.recovery)?)
        || process["stderr_sha256"] != sha256(custody.bytes(&loss.recovery_stderr)?)
    {
        return Err(
            "loss recovery original creation handle/kernel wait/capture custody differs".into(),
        );
    }
    object(
        &recovery,
        &["schema_version", "provider_response", "frontend_delivery"],
        &[],
    )?;
    if number(&recovery, "schema_version")? != 1 {
        return Err("unknown public recovery wrapper".into());
    }
    let response = recovery
        .get("provider_response")
        .ok_or("recovery authority absent")?;
    match text(response, "kind")? {
        "terminal" => {
            let mut terminal = response.clone();
            terminal
                .as_object_mut()
                .ok_or("terminal not object")?
                .remove("kind");
            validate_loss_terminal(
                &terminal,
                &recovery,
                association,
                evidence,
                native,
                key,
                custody,
            )
        }
        "reject" => {
            object(
                response,
                &[
                    "kind",
                    "schema_version",
                    "attempt_id",
                    "nonce",
                    "request_sha256",
                    "rejection",
                ],
                &[],
            )?;
            let disposition = response
                .pointer("/rejection/disposition")
                .ok_or("recovered rejection disposition absent")?;
            if text(disposition, "disposition")? != "postauthorization-failure" {
                return Err("loss recovery lacks postauthorization authority".into());
            }
            validate_loss_terminal(
                disposition
                    .get("receipt")
                    .ok_or("loss recovered receipt absent")?,
                &recovery,
                association,
                evidence,
                native,
                key,
                custody,
            )
        }
        "terminal-retired-v2" => {
            let delivery = recovery
                .get("frontend_delivery")
                .ok_or("retired recovery delivery absent")?;
            object(
                delivery,
                &[
                    "schema_version",
                    "attempt_id",
                    "nonce",
                    "request_sha256",
                    "authority_sha256",
                    "retired_sha256",
                    "retired_confirmed",
                ],
                &[],
            )?;
            if number(delivery, "schema_version")? != 1 {
                return Err("retired recovery delivery revision differs".into());
            }
            for field in ["attempt_id", "nonce", "request_sha256"] {
                if delivery.get(field) != response.get(field) {
                    return Err("retired recovery delivery association differs".into());
                }
            }
            for field in [
                "attempt_id",
                "request_sha256",
                "authority_sha256",
                "retired_sha256",
            ] {
                digest(text(delivery, field)?)?;
            }
            yes(delivery, &["retired_confirmed"])?;
            object(
                response,
                &[
                    "kind",
                    "schema_version",
                    "attempt_id",
                    "nonce",
                    "request_sha256",
                    "terminal_response_sha256",
                    "disposition",
                    "provider_generation",
                    "original_boot_id",
                    "launch_incarnation",
                    "job_identity",
                    "owner_manifest_sha256",
                    "retirement_proof_sha256",
                    "ledger_generation",
                    "completion",
                ],
                &[],
            )?;
            if loss.original_result.is_none()
                || number(response, "schema_version")? != 2
                || text(response, "completion")? != "retirement-complete"
                || text(response, "disposition")? != "posttarget"
                || response.get("attempt_id") != association.get("attempt_id")
                || response.get("request_sha256") != association.get("request_sha256")
                || response.get("nonce").and_then(Value::as_str) != native.attempt_nonce.as_deref()
                || response.get("provider_generation").and_then(Value::as_str)
                    != native.provider_generation.as_deref()
            {
                return Err(
                    "retired tombstone lacks actual original bound failure/retirement".into(),
                );
            }
            for field in [
                "terminal_response_sha256",
                "job_identity",
                "owner_manifest_sha256",
                "retirement_proof_sha256",
                "ledger_generation",
            ] {
                digest(text(response, field)?)?;
            }
            for field in ["original_boot_id", "launch_incarnation"] {
                if text(response, field)?.is_empty() {
                    return Err("retired tombstone identity absent".into());
                }
            }
            Ok(())
        }
        _ => Err("loss recovery authority variant is unavailable/retained/unknown".into()),
    }
}

fn validate_loss_terminal(
    terminal: &Value,
    recovery: &Value,
    association: &Value,
    evidence: &CaseEvidence,
    native: &NativeObservation,
    key: &CaseKey,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    if text(
        terminal.get("payload").ok_or("loss payload absent")?,
        "kind",
    )? == "execution"
        && terminal
            .pointer("/payload/outcome/outcome")
            .and_then(Value::as_str)
            != Some("monitor-failed")
    {
        return Err("loss recovery substituted target/policy completion".into());
    }
    if let Some(path) = evidence
        .windows_loss
        .as_ref()
        .and_then(|loss| loss.original_result.as_deref())
    {
        let original = json(custody.bytes(path)?)?;
        if let Some(cause) = original.pointer("/diagnostics/original")
            && let Some(recovered_cause) = terminal.pointer("/payload/primary_failure")
            && cause != recovered_cause
        {
            return Err(
                "recovered closure replaced retained immutable original first cause".into(),
            );
        }
    }
    let provider_request = custody.bytes(
        evidence
            .provider_request
            .as_deref()
            .ok_or("actual prelaunch fault request absent")?,
    )?;
    let view = serde_json::json!({"format":"memcordon.windows-terminal-observation","revision":1,
        "provider":association.get("provider"),"terminal":terminal,"frontend_delivery":recovery.get("frontend_delivery"),"provider_request":provider_request});
    validate_windows_delivery_and_sample(&view, native, key)?;
    let invocation: NativeInvocation = decode(custody.bytes(&evidence.invocation)?)?;
    validate_windows_request(
        provider_request,
        custody.bytes(
            evidence
                .request
                .as_deref()
                .ok_or("fault request contract absent")?,
        )?,
        &invocation,
        custody.bytes(&invocation.environment)?,
    )
}

pub(crate) fn validate_windows_component(
    receipt: &WindowsNativeComponentReceipt,
    key: &CaseKey,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    match &receipt.payload {
        WindowsNativeComponentPayload::CausalCapture {
            before_journal,
            after_journal,
            first_api,
            first_return,
            first_win32_code,
            second_api,
            second_return,
            second_win32_code,
            invalid_handle_was_null,
        } => {
            if key.family != "W-CAUSAL"
                || key.scenario != "native-code-capture"
                || receipt.test_name
                    != "windows::diagnostics::causal_capture_tests::native_invalid_handle_capture_preserves_first_cause_across_phase_change"
                || first_api != "GetProcessTimes"
                || second_api != "GetExitCodeProcess"
                || *first_return != 0
                || *second_return != 0
                || *first_win32_code != 6
                || *second_win32_code != 6
                || !*invalid_handle_was_null
            {
                return Err("native causal capture exact test/API/code differs".into());
            }
            let before = json(custody.bytes(before_journal)?)?;
            let after = json(custody.bytes(after_journal)?)?;
            for journal in [&before, &after] {
                object(
                    journal,
                    &[
                        "schema_version",
                        "original",
                        "secondary",
                        "sequence",
                        "durable_through_sequence",
                        "loss",
                    ],
                    &[],
                )?;
                if number(journal, "schema_version")? != 1
                    || number(journal, "durable_through_sequence")? != 0
                    || journal.get("loss")
                        != Some(
                            &serde_json::json!({"secondary_events_omitted":0,"secondary_count_saturated":false,"persistence_failure_observed":false,"writer_unavailable":false}),
                        )
                {
                    return Err("native causal capture journal revision/loss differs".into());
                }
                validate_original_failure(
                    journal.get("original").ok_or("captured original absent")?,
                )?;
            }
            if number(&before, "sequence")? != 1
                || number(&after, "sequence")? != 2
                || before["original"] != after["original"]
            {
                return Err("second native failure replaced immutable original or sequence".into());
            }
            empty_array(&before, "secondary")?;
            let secondary = after
                .get("secondary")
                .and_then(Value::as_array)
                .ok_or("captured secondary absent")?;
            if secondary.len() != 1 {
                return Err("captured secondary cardinality differs".into());
            }
            for (event, sequence, operation, phase) in [
                (
                    &before["original"]["observed"]["event"],
                    1,
                    "read-target-exit",
                    "authorized-before-resume",
                ),
                (&secondary[0], 2, "poll-target", "monitoring"),
            ] {
                validate_original_failure(&serde_json::json!({"observed":{"event":event}}))?;
                if event["sequence"] != sequence
                    || event["origin"] != "launcher"
                    || event["category"] != "monitor"
                    || event["operation"] != operation
                    || event["code"] != "target-query"
                    || event["native_code"] != serde_json::json!({"win32":6})
                    || event["observed_phase"] != phase
                    || event["safe_detail"] != "no-additional-detail"
                    || event["detail_redacted"] != true
                    || event["detail_truncated"] != false
                    || !event["terminalization_reference"].is_null()
                {
                    return Err("actual native causal event domain/order/phase differs".into());
                }
            }
            Ok(())
        }
        WindowsNativeComponentPayload::ReplayOwnedOutbox {
            record,
            after_record,
            first_response,
            repeated_response,
            duplicate_refusal,
            nonce_refusal,
            request_refusal,
            attempt_id,
            nonce,
            request_sha256,
            fixture_resource_claims,
            installed_state_accessed,
            ack_record,
            staged_ack,
            completed_ack,
            retired_response,
            repeated_retired_response,
            active_record_refusal,
            ack_nonce_refusal,
            ack_caller_refusal,
            outbox_absent_after_ack,
            available_journal,
            expired_journal,
            expiry_record,
            retention,
            pre_expiry_clock,
            expired_clock,
            same_boot,
        } => {
            if key.family != "W-REPLAY"
                || ![
                    "durable-replay",
                    "lost-publication-response",
                    "lost-acknowledgement",
                    "expiry-authority",
                ]
                .contains(&key.scenario.as_str())
                || receipt.test_name
                    != "windows_postauthorization_retirement::suspended_postauthorization_rejection_stages_replays_and_retires_bound_outbox"
                || !*fixture_resource_claims
                || *installed_state_accessed
                || !*outbox_absent_after_ack
                || !*same_boot
                || duplicate_refusal != "attempt is not ready for a create-once terminal outbox"
                || nonce_refusal != "pending terminal response is not bound to the replay request"
                || request_refusal
                    != "pending terminal replay credentials are not bound to the exact attempt"
                || active_record_refusal != "ACK tombstone still has a durable attempt record"
                || [ack_nonce_refusal, ack_caller_refusal].iter().any(|value| {
                    value.as_str()
                        != "terminal ACK tombstone does not match authenticated replay caller"
                })
            {
                return Err("owned component replay source/refusal/ownership differs".into());
            }
            digest(attempt_id)?;
            digest(request_sha256)?;
            let bytes = custody.bytes(record)?;
            if record == after_record
                || bytes != custody.bytes(after_record)?
                || bytes != custody.bytes(expiry_record)?
                || custody.bytes(first_response)? != custody.bytes(repeated_response)?
                || custody.bytes(retired_response)? != custody.bytes(repeated_retired_response)?
            {
                return Err(
                    "owned replay/refusal/expiry or repeated ACK mutated actual committed bytes"
                        .into(),
                );
            }
            let initial = json(bytes)?;
            validate_windows_record_v4(&initial)?;
            if text(&initial, "attempt_id")? != attempt_id
                || text(&initial, "nonce")? != nonce
                || text(&initial, "request_sha256")? != request_sha256
                || text(&initial, "lifecycle")? != "outbox-staged"
                || text(&initial, "terminal_response_json")?.as_bytes()
                    != custody.bytes(first_response)?
            {
                return Err("owned replay durable outbox/response association differs".into());
            }
            let mut ack = json(custody.bytes(ack_record)?)?;
            validate_windows_record_v4(&ack)?;
            if text(&ack, "lifecycle")? != "ack-committed"
                || number(&ack, "record_revision")? != number(&initial, "record_revision")? + 1
            {
                return Err("owned ACK did not advance exact committed outbox".into());
            }
            for field in ["lifecycle", "record_revision", "integrity_sha256"] {
                ack[field] = initial[field].clone();
            }
            if ack != initial {
                return Err("ACK changed immutable outbox association/original".into());
            }
            let staged = json(custody.bytes(staged_ack)?)?;
            let mut completed = json(custody.bytes(completed_ack)?)?;
            object(
                &staged,
                &["attempt_id", "request_sha256", "acknowledged"],
                &[],
            )?;
            object(
                &completed,
                &["attempt_id", "request_sha256", "acknowledged"],
                &[],
            )?;
            if text(&staged, "attempt_id")? != attempt_id
                || text(&staged, "request_sha256")? != request_sha256
                || staged["acknowledged"]["retirement_complete"] != false
                || completed["acknowledged"]["retirement_complete"] != true
            {
                return Err(
                    "owned staged/completed ACK association or actual retirement differs".into(),
                );
            }
            completed["acknowledged"]["retirement_complete"] = serde_json::json!(false);
            if completed != staged {
                return Err("ACK completion rewrote its original authority".into());
            }
            let tombstone = &staged["acknowledged"];
            if tombstone["caller_process_identity"] != initial["caller_process_identity"]
                || tombstone["caller_token_sha256"] != initial["caller_token_sha256"]
                || tombstone["provider_generation"] != initial["provider_generation"]
                || tombstone["launch_incarnation"] != initial["launch_incarnation"]
                || tombstone["retired"]["nonce"] != serde_json::json!(nonce)
                || tombstone["retired"]["request_sha256"] != serde_json::json!(request_sha256)
            {
                return Err(
                    "owned ACK caller/provider/request differs from physical outbox".into(),
                );
            }
            if retention != &initial["diagnostic_retention"]
                || number(retention, "expires_monotonic_millis")? != *expired_clock
                || pre_expiry_clock.checked_add(1) != Some(*expired_clock)
                || *pre_expiry_clock < number(retention, "admitted_monotonic_millis")?
            {
                return Err("component expiry clock differs from exact declared boundary".into());
            }
            let available = json(custody.bytes(available_journal)?)?;
            let expired = json(custody.bytes(expired_journal)?)?;
            if available != initial["causal_diagnostics"]
                || expired["original"]
                    != serde_json::json!({"unavailable":{"reason":"retention-expired"}})
                || !expired["secondary"].as_array().is_some_and(Vec::is_empty)
            {
                return Err(
                    "component expiry projection differs or rewrites retained authority".into(),
                );
            }
            Ok(())
        }
        WindowsNativeComponentPayload::BindingSeed {
            before_record,
            after_record,
            replacement_observation,
            refusal,
            stores_before_refusal,
            stores_after_refusal,
        } => {
            if key.family != "W-BINDING"
                || key.scenario != "seed-replacement"
                || receipt.test_name
                    != "windows_postauthorization_retirement::terminal_seed_freezes_before_proof_and_rejects_replacement"
                || refusal != "terminal seed cannot be frozen outside retiring authority"
                || *stores_before_refusal != 1
                || *stores_after_refusal != 1
                || before_record == after_record
                || custody.bytes(before_record)? != custody.bytes(after_record)?
            {
                return Err("seed replacement mutated frozen authority or differs from exact component refusal".into());
            }
            let record = json(custody.bytes(before_record)?)?;
            validate_windows_fixture_record(&record)?;
            let seed = record
                .get("terminal_seed")
                .filter(|value| value.is_object())
                .ok_or("component frozen seed absent")?;
            object(
                seed,
                &[
                    "schema_version",
                    "attempt_id",
                    "nonce",
                    "request_sha256",
                    "process_observation",
                    "primary_failure",
                ],
                &[],
            )?;
            if number(seed, "schema_version")? != 2
                || text(&record, "state")? != "terminating"
                || !record.get("retirement_proof").is_some_and(Value::is_null)
                || seed.get("process_observation")
                    != Some(&json(custody.bytes(replacement_observation)?)?)
            {
                return Err("component seed replacement/proof authority differs".into());
            }
            for field in ["attempt_id", "nonce", "request_sha256"] {
                if seed.get(field) != record.get(field) {
                    return Err("component frozen seed association differs".into());
                }
            }
            Ok(())
        }
        WindowsNativeComponentPayload::BindingProof {
            before_record,
            after_refusal_record,
            after_matching_record,
            mismatched_receipt,
            matching_receipt,
            refusal,
        } => {
            if key.family != "W-BINDING"
                || key.scenario != "proof-mismatch"
                || receipt.test_name
                    != "windows_postauthorization_retirement::frozen_seed_accepts_only_matching_later_retirement_proof"
                || refusal != "terminal proof differs from the frozen seed"
                || before_record == after_refusal_record
                || custody.bytes(before_record)? != custody.bytes(after_refusal_record)?
            {
                return Err("mismatched proof mutated frozen component authority".into());
            }
            let before = json(custody.bytes(before_record)?)?;
            let after = json(custody.bytes(after_matching_record)?)?;
            validate_windows_fixture_record(&before)?;
            validate_windows_fixture_record(&after)?;
            let matching = json(custody.bytes(matching_receipt)?)?;
            let mismatched = json(custody.bytes(mismatched_receipt)?)?;
            let mut expected_mismatch = matching.clone();
            let birth = matching
                .pointer("/process_observation/root_identity/creation_time_100ns")
                .and_then(Value::as_u64)
                .ok_or("component matching root birth absent")?;
            *expected_mismatch
                .pointer_mut("/process_observation/root_identity/creation_time_100ns")
                .ok_or("component matching root absent")? = Value::from(
                birth
                    .checked_add(1)
                    .ok_or("component root birth overflow")?,
            );
            if expected_mismatch != mismatched
                || text(&before, "lifecycle")? != "retiring"
                || text(&after, "lifecycle")? != "proof-ready"
                || !before.get("retirement_proof").is_some_and(Value::is_null)
                || after.get("retirement_proof") != matching.get("retirement_proof")
                || !before.get("terminal_seed").is_some_and(Value::is_object)
                || before.get("terminal_seed") != after.get("terminal_seed")
                || after.pointer("/terminal_seed/process_observation")
                    != matching.get("process_observation")
            {
                return Err("component matching/mismatched proof transition differs".into());
            }
            for field in ["attempt_id", "nonce", "request_sha256"] {
                if matching.get(field) != before.get(field) {
                    return Err("component proof attempt association differs".into());
                }
            }
            let mut expected_after = before.clone();
            for field in ["lifecycle", "terminal_seed", "retirement_proof"] {
                *expected_after
                    .get_mut(field)
                    .ok_or("component staged field absent")? = after
                    .get(field)
                    .cloned()
                    .ok_or("component staged field absent")?;
            }
            if expected_after != after {
                return Err(
                    "component proof staging replaced unrelated state or original cause".into(),
                );
            }
            Ok(())
        }
        WindowsNativeComponentPayload::BindingReceiptless {
            before_record,
            after_record,
            response,
            original,
            refusal,
        } => {
            if !((key.family == "W-BINDING" && key.scenario == "receiptless-posttarget")
                || (key.family == "W-CAUSAL" && key.scenario == "receiptless-first-cause"))
                || receipt.test_name
                    != "windows_postauthorization_retirement::receiptless_posttarget_rejection_cannot_bypass_terminal_binding"
                || refusal != "terminal outbox response is not bound and consistent for the attempt"
                || before_record == after_record
            {
                return Err(
                    "receiptless response differs from exact component binding refusal".into(),
                );
            }
            let before = json(custody.bytes(before_record)?)?;
            let after = json(custody.bytes(after_record)?)?;
            validate_windows_fixture_record(&before)?;
            validate_windows_fixture_record(&after)?;
            let retained = json(custody.bytes(original)?)?;
            validate_original_failure(&retained)?;
            // 1234 is the frozen protocol vector's declared native value. This
            // component test does not establish an observed Win32 API error.
            let expected_original = serde_json::json!({"observed":{"event":{"sequence":1,"origin":"launcher",
                "category":"monitor","operation":"observe-process-identity","code":"process-inventory-observation",
                "native_code":{"win32":1234},"observed_phase":"monitoring","safe_detail":"no-additional-detail",
                "detail_redacted":true,"detail_truncated":false,"terminalization_reference":null}}});
            if retained != expected_original {
                return Err(
                    "receiptless component original differs from frozen protocol vector".into(),
                );
            }
            let rejected = json(custody.bytes(response)?)?;
            let expected_response = serde_json::json!({"kind":"reject","schema_version":3,
                "attempt_id":before["attempt_id"],"nonce":before["nonce"],"request_sha256":before["request_sha256"],
                "rejection":{"schema_version":2,"code":"MCSEALED-WINDOWS-CERTIFICATION-FAULT","phase":"retirement",
                    "detail":"synthetic preauthorization failure","os_code":5,"target_created":true,"target_released":false,
                    "cleanup_attempted":true,"restart_safety":{"direct_child_reaped":true,"workload_empty":true,
                        "helpers_reaped":true,"containment_removed":true,"containment_incapable_of_live_members":true,
                        "sealed_boundary_retired":true,"errors":[]},
                    "disposition":{"disposition":"preauthorization","terminal_ack_required":true}}});
            if rejected != expected_response {
                return Err("receiptless response differs from frozen preauthorization-shaped protocol vector".into());
            }
            if rejected.get("kind").and_then(Value::as_str) != Some("reject")
                || before.pointer("/causal_diagnostics/original") != Some(&retained)
                || after.pointer("/causal_diagnostics/original") != Some(&retained)
                || before
                    .get("terminal_response_json")
                    .is_some_and(|value| !value.is_null())
                || after
                    .get("terminal_response_json")
                    .is_some_and(|value| !value.is_null())
            {
                return Err(
                    "receiptless response replaced original or published terminal authority".into(),
                );
            }
            for field in ["attempt_id", "nonce", "request_sha256"] {
                if rejected.get(field) != before.get(field) {
                    return Err("receiptless response component association differs".into());
                }
            }
            let secondary = after
                .pointer("/causal_diagnostics/secondary")
                .and_then(Value::as_array)
                .ok_or("receiptless secondary absent")?;
            if secondary.len() != 1 {
                return Err("receiptless component secondary cardinality differs".into());
            }
            validate_windows_receiptless_cause(&retained, &secondary[0])?;
            if secondary.len() != 1
                || secondary[0]["operation"] != "validate-terminal-response"
                || secondary[0]["terminalization_reference"] != "first-error"
                || secondary[0]["sequence"] != 2
                || secondary[0]["category"] != "terminalization"
                || secondary[0]["code"] != "terminal-binding"
                || secondary[0]["observed_phase"] != "terminalizing"
                || secondary[0]["native_code"] != Value::Null
                || secondary[0]["origin"] != "launcher"
                || secondary[0]["safe_detail"] != "no-additional-detail"
                || secondary[0]["detail_redacted"] != true
                || secondary[0]["detail_truncated"] != false
            {
                return Err(
                    "receiptless response lacks exact first-error terminalization observation"
                        .into(),
                );
            }
            let mut expected_diagnostics = before["causal_diagnostics"].clone();
            if expected_diagnostics["sequence"] != 1
                || expected_diagnostics["secondary"] != serde_json::json!([])
            {
                return Err("receiptless component baseline has unrelated diagnostics".into());
            }
            expected_diagnostics["sequence"] = Value::from(2);
            expected_diagnostics["secondary"] = Value::from(secondary.clone());
            if expected_diagnostics != after["causal_diagnostics"] {
                return Err("receiptless refusal changed diagnostic loss or durability".into());
            }
            let terminalization = &after["terminalization"];
            if terminalization["owner"] != "launcher-worker"
                || terminalization["checkpoint"] != "retained-failure"
                || terminalization["sequence"].as_u64()
                    != before["terminalization"]["sequence"]
                        .as_u64()
                        .and_then(|n| n.checked_add(1))
                || terminalization
                    .pointer("/last_error/stage")
                    .and_then(Value::as_str)
                    != Some("response-validate")
                || terminalization
                    .pointer("/last_error/error_code")
                    .and_then(Value::as_str)
                    != Some("MCSEALED-WINDOWS-TERMINAL-RESPONSE")
            {
                return Err(
                    "receiptless refusal lacks exact retained terminalization failure".into(),
                );
            }
            let failure = &terminalization["last_error"];
            object(
                failure,
                &[
                    "stage",
                    "error_code",
                    "detail",
                    "native_code",
                    "observed_unix_millis",
                ],
                &[],
            )?;
            if failure["detail"].as_str() != Some(refusal.as_str())
                || failure["native_code"] != Value::Null
                || terminalization
                    .get("secondary_errors")
                    .is_some_and(|value| value != &serde_json::json!([]))
            {
                return Err(
                    "receiptless component terminalization invented secondary/native failure"
                        .into(),
                );
            }
            let mut expected = before.clone();
            *expected
                .get_mut("causal_diagnostics")
                .ok_or("receiptless diagnostics absent")? = after["causal_diagnostics"].clone();
            *expected
                .get_mut("terminalization")
                .ok_or("receiptless terminalization absent")? = terminalization.clone();
            if expected != after {
                return Err("receiptless refusal mutated unrelated component state".into());
            }
            Ok(())
        }
        WindowsNativeComponentPayload::BindingGeneration {
            record,
            attempt_id,
            provider_generation,
            substituted_generation,
            refusal,
        } => {
            if key.family != "W-BINDING"
                || key.scenario != "generation-substitution"
                || receipt.test_name
                    != "windows::record::record_fault_tests::native_durable_record_rejects_provider_generation_substitution"
                || refusal != "MCSEALED-WINDOWS-ATTEMPT-RECORD-AUTH: reason=v4-binding"
            {
                return Err("generation substitution exact native test/refusal differs".into());
            }
            digest(attempt_id)?;
            digest(provider_generation)?;
            digest(substituted_generation)?;
            if substituted_generation != &sha256(provider_generation.as_bytes())
                || substituted_generation == provider_generation
            {
                return Err("generation substitution does not change the measured exact original generation".into());
            }
            let record = json(custody.bytes(record)?)?;
            validate_windows_record_v4(&record)?;
            if number(&record, "record_revision")? != 1
                || text(&record, "attempt_id")? != attempt_id
                || text(&record, "provider_generation")? != provider_generation
            {
                return Err(
                    "generation substitution record/attempt/source generation differs".into(),
                );
            }
            Ok(())
        }
        WindowsNativeComponentPayload::WriterFrozen { observations } => {
            if key.family != "W-WRITER"
                || key.scenario != "frozen-live"
                || receipt.test_name
                    != "windows::record::record_fault_tests::frozen_native_publication_does_not_own_workload_job_cleanup"
                || observations.len() != 2
            {
                return Err("frozen writer exact native test/rows differ".into());
            }
            let owners: BTreeSet<_> = observations
                .iter()
                .map(|row| row.cleanup_owner.as_str())
                .collect();
            if owners != BTreeSet::from(["guardian", "worker"]) {
                return Err("frozen writer omits/duplicates cleanup owner".into());
            }
            for row in observations {
                if row.job_active_before != 2
                    || row.job_active_after != 0
                    || row.job_members.len() != 2
                    || !row.writer_frozen_during_cleanup
                    || row.cleanup_publication_confirmed
                    || !row.guardian_retired_during_cleanup
                    || row.worker_retired_during_cleanup != (row.cleanup_owner == "guardian")
                {
                    return Err(
                        "frozen writer conflates cleanup publication with native Job retirement"
                            .into(),
                    );
                }
                let mut identities = BTreeSet::new();
                for member in &row.job_members {
                    if member.identity.process_id == 0
                        || member.identity.creation_time_100ns == 0
                        || !member.held_before_cleanup
                        || !member.retirement_observed
                        || !identities.insert((
                            member.identity.process_id,
                            member.identity.creation_time_100ns,
                        ))
                    {
                        return Err(
                            "frozen writer actual held Job members missing/duplicated".into()
                        );
                    }
                }
                for identity in [&row.worker_identity, &row.guardian_identity] {
                    if identity.process_id == 0
                        || identity.creation_time_100ns == 0
                        || !identities.insert((identity.process_id, identity.creation_time_100ns))
                    {
                        return Err("frozen writer owner native identity absent/aliased".into());
                    }
                }
                let record = json(custody.bytes(&row.after_record)?)?;
                validate_windows_record_v4(&record)?;
                let original = json(custody.bytes(&row.original)?)?;
                validate_original_failure(&original)?;
                if number(&record, "record_revision")? != 1
                    || record.pointer("/cleanup_state/termination_requested")
                        != Some(&Value::Bool(false))
                    || record.pointer("/causal_diagnostics/original") != Some(&original)
                {
                    return Err(
                        "frozen writer changed original or invented confirmed cleanup publication"
                            .into(),
                    );
                }
            }
            Ok(())
        }
        WindowsNativeComponentPayload::WriterReservation {
            attempt_id,
            request_sha256,
            owner_identity,
            owner_held_live_during_refusal,
            before_reservation,
            after_refusal_reservation,
            retirement_without_local_proof,
            writer_frozen_during_refusal,
            writer_joined_before_retirement,
            published_record,
            local_writer_retirement_proved,
            reservation_absent_after_retirement,
        } => {
            if key.family != "W-WRITER"
                || key.scenario != "settlement-reservation"
                || receipt.test_name
                    != "windows::record::record_fault_tests::native_settlement_reservation_requires_local_writer_retirement"
                || !owner_held_live_during_refusal
                || !writer_frozen_during_refusal
                || !writer_joined_before_retirement
                || !local_writer_retirement_proved
                || !reservation_absent_after_retirement
                || owner_identity.process_id == 0
                || owner_identity.creation_time_100ns == 0
                || retirement_without_local_proof
                    != "cannot release a live writer reservation without local retirement proof"
            {
                return Err(
                    "writer settlement lacks actual local retirement/held refusal sequence".into(),
                );
            }
            digest(attempt_id)?;
            digest(request_sha256)?;
            let before = custody.bytes(before_reservation)?;
            let after = custody.bytes(after_refusal_reservation)?;
            if before_reservation == after_refusal_reservation || before != after {
                return Err("live writer refusal mutated reservation".into());
            }
            let reservation = json(before)?;
            object(
                &reservation,
                &[
                    "format",
                    "revision",
                    "attempt_id",
                    "request_sha256",
                    "owner_process_identities",
                    "workload_reservation",
                ],
                &[],
            )?;
            if text(&reservation, "format")? != "memcordon.windows-admission-record"
                || number(&reservation, "revision")? != 1
                || text(&reservation, "attempt_id")? != attempt_id
                || text(&reservation, "request_sha256")? != request_sha256
                || reservation.get("workload_reservation") != Some(&Value::Bool(true))
                || reservation.get("owner_process_identities")
                    != Some(&serde_json::json!([owner_identity]))
            {
                return Err("writer admission reservation native owner/binding differs".into());
            }
            let published = json(custody.bytes(published_record)?)?;
            validate_windows_record_v4(&published)?;
            if number(&published, "record_revision")? != 1
                || text(&published, "attempt_id")? != attempt_id
                || text(&published, "request_sha256")? != request_sha256
            {
                return Err("joined writer publication reservation association differs".into());
            }
            Ok(())
        }
        WindowsNativeComponentPayload::Writer { observations } => {
            if key.family != "W-WRITER" {
                return Err(
                    "publication matrix substituted another native component obligation".into(),
                );
            }
            let (native_test, expected_phases): (&str, &[&str]) = match key.scenario.as_str() {
                "serialization-error" | "write-error" | "readback-error" => (
                    "native_publication_fault_matrix_preserves_original_and_honest_commit_boundary",
                    &[
                        "read-previous",
                        "serialize",
                        "create-staging",
                        "write-prefix",
                        "write-remainder",
                        "flush",
                        "rename",
                        "after-rename",
                        "readback",
                    ],
                ),
                "rename-error" => (
                    "native_rename_sharing_failure_retains_typed_code_and_original",
                    &["native-sharing-rename"],
                ),
                "crash-before-durable" | "crash-after-durable" => (
                    "native_publisher_process_exit_preserves_atomic_old_or_new_record",
                    &["crash-before-rename", "crash-after-rename"],
                ),
                _ => {
                    return Err(
                        "writer payload cannot substitute frozen-live/settlement evidence".into(),
                    );
                }
            };
            if receipt.test_name != format!("windows::record::record_fault_tests::{native_test}") {
                return Err("native writer actual exact test name differs".into());
            }
            let phases: BTreeSet<_> = observations
                .iter()
                .map(|observation| observation.phase.as_str())
                .collect();
            let expected: BTreeSet<_> = expected_phases.iter().copied().collect();
            if observations.len() != expected.len() || phases != expected {
                return Err(
                    "native publication matrix omits/duplicates an actual required phase".into(),
                );
            }
            for observation in observations {
                if observation.before_record == observation.after_record {
                    return Err("publication observation compares one artifact to itself".into());
                }
                let crash = observation.phase.starts_with("crash-");
                if observation.publication_rejected == crash || observation.caller_ack_revision != 1
                {
                    return Err("native publication return/crash was conflated or caller object substituted".into());
                }
                if crash {
                    let publisher = observation
                        .publisher_process
                        .as_ref()
                        .ok_or("crash publisher held identity missing")?;
                    if publisher.process_id == 0
                        || publisher.creation_time_100ns == 0
                        || !publisher.held_before_input_delivery
                        || !publisher.retirement_observed
                        || publisher.exit_status != 73
                        || observation.native_code.is_some()
                    {
                        return Err(
                            "publisher crash lacks actual held identity/native wait73".into()
                        );
                    }
                } else if observation.publisher_process.is_some() {
                    return Err("returned-error publication invents crashed publisher".into());
                }
                if observation.phase == "native-sharing-rename"
                    && !matches!(observation.native_code.as_ref(), Some(WindowsNativeComponentCode::Win32(value)) if *value != 0)
                {
                    return Err("real native rename-sharing error code absent".into());
                }
                if observation.native_code.as_ref().is_some_and(
                    |code| !matches!(code, WindowsNativeComponentCode::Win32(value) if *value != 0),
                ) {
                    return Err("writer invents success/unknown native error code".into());
                }
                let before_bytes = custody.bytes(&observation.before_record)?;
                let after_bytes = custody.bytes(&observation.after_record)?;
                let mut before = json(before_bytes)?;
                let mut after = json(after_bytes)?;
                validate_windows_record_v4(&before)?;
                validate_windows_record_v4(&after)?;
                let original = json(custody.bytes(&observation.original)?)?;
                validate_original_failure(&original)?;
                if before.pointer("/causal_diagnostics/original") != Some(&original)
                    || after.pointer("/causal_diagnostics/original") != Some(&original)
                    || number(&before, "record_revision")? != 1
                    || number(&after, "record_revision")? != observation.persisted_revision
                {
                    return Err(
                        "publication lost actual immutable original/revision observation".into(),
                    );
                }
                if ["after-rename", "readback", "crash-after-rename"]
                    .contains(&observation.phase.as_str())
                {
                    if observation.persisted_revision != 2 {
                        return Err("post-publication failure hid committed native revision".into());
                    }
                    for record in [&mut before, &mut after] {
                        let object = record.as_object_mut().ok_or("native record not object")?;
                        object.remove("record_revision");
                        object.remove("integrity_sha256");
                    }
                    if before != after {
                        return Err(
                            "native publication changed frozen authority/first-cause payload"
                                .into(),
                        );
                    }
                } else if observation.persisted_revision != 1 || before_bytes != after_bytes {
                    return Err("prepublication failure mutated native authority".into());
                }
            }
            Ok(())
        }
    }
}

fn validate_windows_record_v4(record: &Value) -> VerificationResult<()> {
    validate_windows_record_fields(record, true)
}

fn validate_windows_fixture_record(record: &Value) -> VerificationResult<()> {
    if number(record, "record_revision")? != 0 || !text(record, "integrity_sha256")?.is_empty() {
        return Err("component fixture was promoted to durable native authority".into());
    }
    validate_windows_record_fields(record, false)
}

fn validate_windows_record_fields(record: &Value, durable: bool) -> VerificationResult<()> {
    object(
        record,
        &[
            "schema_version",
            "attempt_id",
            "provider_generation",
            "boot_identity",
            "launch_incarnation",
            "nonce",
            "request_sha256",
            "caller_process_identity",
            "caller_token_sha256",
            "job_identity_sha256",
            "guardian_identity",
            "worker_identity",
            "target_identity",
            "state",
            "lifecycle",
            "authorization_unix_millis",
            "resume_attempted",
            "target_released",
            "cleanup_state",
            "owner_manifest",
            "recovery_authorization",
            "terminal_publication_reserved",
            "terminal_seed",
            "retirement_proof",
            "terminalization",
            "causal_diagnostics",
            "diagnostic_retention",
            "workload_admission",
            "workload_checkpoint",
            "record_revision",
            "provider_incarnation",
            "integrity_sha256",
        ],
        &[
            "worker_thread_identity",
            "terminal_response_json",
            "terminal_disposition",
        ],
    )?;
    if number(record, "schema_version")? != 4 {
        return Err("unknown protected native record revision".into());
    }
    if ![
        "boundary-created",
        "guardian-ready",
        "target-created-suspended",
        "authorized",
        "terminating",
        "empty",
    ]
    .contains(&text(record, "state")?)
        || ![
            "executing",
            "retiring",
            "proof-ready",
            "outbox-staged",
            "ack-committed",
            "retirement-complete",
            "retained",
            "quarantined",
        ]
        .contains(&text(record, "lifecycle")?)
    {
        return Err("unknown native record authority state".into());
    }
    let cleanup = record.get("cleanup_state").ok_or("record cleanup absent")?;
    object(
        cleanup,
        &[
            "termination_requested",
            "active_processes_zero",
            "guardian_reaped",
            "final_handles_closed",
        ],
        &[],
    )?;
    for field in [
        "termination_requested",
        "active_processes_zero",
        "guardian_reaped",
        "final_handles_closed",
    ] {
        if !cleanup.get(field).is_some_and(Value::is_boolean) {
            return Err("record cleanup flag not boolean".into());
        }
    }
    let terminalization = record
        .get("terminalization")
        .ok_or("record terminalization absent")?;
    object(
        terminalization,
        &["schema_version", "owner", "sequence", "checkpoint"],
        &["last_error", "secondary_errors"],
    )?;
    if number(terminalization, "schema_version")? != 1
        || ![
            "launcher-worker",
            "control-service",
            "startup-recovery",
            "guardian-recovery",
        ]
        .contains(&text(terminalization, "owner")?)
        || ![
            "executing",
            "cleanup-requested",
            "cleanup-proof-ready",
            "rejection-building",
            "outbox-staging",
            "outbox-staged",
            "ack-retiring",
            "retained-failure",
        ]
        .contains(&text(terminalization, "checkpoint")?)
    {
        return Err("unknown native terminalization authority".into());
    }
    for field in [
        "attempt_id",
        "request_sha256",
        "caller_token_sha256",
        "job_identity_sha256",
    ] {
        digest(text(record, field)?)?;
    }
    if durable {
        digest(text(record, "integrity_sha256")?)?;
    }
    let causal = record
        .get("causal_diagnostics")
        .ok_or("native causal diagnostics missing")?;
    object(
        causal,
        &[
            "schema_version",
            "original",
            "secondary",
            "sequence",
            "durable_through_sequence",
            "loss",
        ],
        &[],
    )?;
    if number(causal, "schema_version")? != 1 {
        return Err("unknown native causal diagnostic revision".into());
    }
    validate_original_failure(
        causal
            .get("original")
            .ok_or("native original failure missing")?,
    )
}

pub(crate) fn validate_windows_runtime(
    result: &Value,
    terminal_bytes: &[u8],
    native: &NativeObservation,
    key: &CaseKey,
) -> VerificationResult<()> {
    let runtime = result.get("runtime").ok_or("Windows runtime missing")?;
    object(runtime, &["kind", "observation"], &[])?;
    if text(runtime, "kind")? != "windows-sealed" {
        return Err("Windows installed product did not use sealed runtime".into());
    }
    let observation = runtime
        .get("observation")
        .ok_or("Windows observation missing")?;
    let fields = [
        "schema_version",
        "service_identity",
        "caller_token_authenticated",
        "initial_target_token_matches_caller",
        "credential_transition_disposition",
        "job_membership_independent_of_token",
        "job_created",
        "job_limits_verified",
        "kill_on_close_verified",
        "breakaway_denied",
        "completion_port_associated",
        "guardian_ready",
        "target_created_suspended",
        "job_list_applied_at_creation",
        "handle_list_applied_at_creation",
        "target_job_membership_verified",
        "target_still_suspended_during_verification",
        "inherited_handles_verified",
        "target_released",
        "terminate_job_invoked",
        "active_processes_zero",
        "direct_target_reaped",
        "relays_retired",
        "guardian_reaped",
        "final_job_handles_closed",
    ];
    object(
        observation,
        &fields,
        &["loader_qualification", "frontend_delivery"],
    )?;
    if number(observation, "schema_version")? != 2 {
        return Err("Windows native observation revision differs".into());
    }
    yes(
        observation,
        &[
            "caller_token_authenticated",
            "initial_target_token_matches_caller",
            "job_membership_independent_of_token",
            "job_created",
            "job_limits_verified",
            "kill_on_close_verified",
            "breakaway_denied",
            "completion_port_associated",
            "guardian_ready",
            "target_created_suspended",
            "job_list_applied_at_creation",
            "handle_list_applied_at_creation",
            "target_job_membership_verified",
            "target_still_suspended_during_verification",
            "inherited_handles_verified",
            "target_released",
            "active_processes_zero",
            "direct_target_reaped",
            "relays_retired",
            "guardian_reaped",
            "final_job_handles_closed",
        ],
    )?;
    let sidecar = json(terminal_bytes)?;
    validate_windows_delivery_and_sample(&sidecar, native, key)?;
    object(
        &sidecar,
        &[
            "format",
            "revision",
            "provider",
            "terminal",
            "frontend_delivery",
            "provider_request",
        ],
        &[],
    )?;
    if text(&sidecar, "format")? != "memcordon.windows-terminal-observation"
        || number(&sidecar, "revision")? != 1
    {
        return Err("Windows terminal sidecar format differs".into());
    }
    if sidecar.get("provider") != result.pointer("/provider_association/provider") {
        return Err("sidecar/result provider differs".into());
    }
    if sidecar.get("frontend_delivery") != observation.get("frontend_delivery") {
        return Err("frontend delivery differs from public runtime projection".into());
    }
    let receipt = sidecar.get("terminal").ok_or("terminal receipt missing")?;
    object(
        receipt,
        &[
            "schema_version",
            "attempt_id",
            "nonce",
            "request_sha256",
            "payload",
            "process_observation",
            "restart_safety",
            "retirement_proof",
        ],
        &["policy_enforcement", "cleanup_process_creation"],
    )?;
    if number(receipt, "schema_version")? != 2
        || receipt.get("attempt_id").and_then(Value::as_str) != native.attempt_id.as_deref()
        || receipt.get("request_sha256").and_then(Value::as_str) != native.request_sha256.as_deref()
    {
        return Err("terminal receipt attempt/request/revision differs".into());
    }
    let proof = receipt
        .get("retirement_proof")
        .ok_or("native retirement proof missing")?;
    object(
        proof,
        &[
            "schema_version",
            "source",
            "attempt_id",
            "nonce",
            "request_sha256",
            "provider_generation",
            "launch_incarnation",
            "original_boot_id",
            "job_identity",
            "owner_manifest_sha256",
            "target_completion_observed",
            "native_job_empty_observed",
            "relay_closure_observed",
            "guardian_completion_observed",
            "owner_capabilities_closed",
            "launch_gate_closed",
            "policy_reference_bound",
        ],
        &["guardian_receipt_sha256", "current_boot_id"],
    )?;
    if number(proof, "schema_version")? != 2
        || !["live-native", "guardian-recovery", "prior-boot"].contains(&text(proof, "source")?)
    {
        return Err("unknown native retirement proof variant".into());
    }
    for field in ["attempt_id", "nonce", "request_sha256"] {
        if proof.get(field) != receipt.get(field) {
            return Err("nested retirement proof binding differs".into());
        }
    }
    validate_windows_proof_matrix(receipt)?;
    let payload = receipt.get("payload").ok_or("terminal payload missing")?;
    match text(payload, "kind")? {
        "execution" => {
            object(
                payload,
                &[
                    "kind",
                    "child_pid",
                    "duration_millis",
                    "authorization_offset_millis",
                    "outcome",
                    "boundary_detail",
                ],
                &[],
            )?;
            if payload.get("child_pid").and_then(Value::as_u64) != native.root_pid.map(u64::from) {
                return Err("terminal execution root differs".into());
            }
            // The complete emitted native boundary is compared to its public
            // observation, not inferred from top-level cleanup or samples.
            let boundary = payload
                .get("boundary_detail")
                .ok_or("native boundary missing")?;
            let mut expected_boundary = observation.clone();
            expected_boundary
                .as_object_mut()
                .ok_or("native Windows observation is not an object")?
                .remove("frontend_delivery");
            let mut actual_boundary = boundary.clone();
            let actual = actual_boundary
                .as_object_mut()
                .ok_or("Windows terminal boundary is not an object")?;
            if actual.remove("mechanism") != Some(Value::String("windows-job-object-v2".into()))
                || actual_boundary != expected_boundary
            {
                return Err("Windows native terminal/public boundary projection differs".into());
            }
        }
        "recovered-closure" => {
            object(
                payload,
                &[
                    "kind",
                    "primary_failure",
                    "target_creation_observed",
                    "resume_attempted",
                ],
                &[],
            )?;
            if native.origin != OutcomeOrigin::ProviderFailure {
                return Err("recovered closure substituted for target outcome".into());
            }
            let primary = payload
                .get("primary_failure")
                .ok_or("original failure missing")?;
            if primary.is_null() || result.get("diagnostics").is_none_or(Value::is_null) {
                return Err("recovery lost immutable original cause".into());
            }
        }
        _ => return Err("unknown authenticated terminal payload variant".into()),
    }
    Ok(())
}

pub(crate) fn validate_windows_delivery_and_sample(
    sidecar: &Value,
    native: &NativeObservation,
    key: &CaseKey,
) -> VerificationResult<()> {
    object(
        sidecar,
        &[
            "format",
            "revision",
            "provider",
            "terminal",
            "frontend_delivery",
            "provider_request",
        ],
        &[],
    )?;
    if text(sidecar, "format")? != "memcordon.windows-terminal-observation"
        || number(sidecar, "revision")? != 1
    {
        return Err("Windows sidecar format/revision differs".into());
    }
    let provider = sidecar.get("provider").ok_or("sidecar provider missing")?;
    object(
        provider,
        &["generation", "source_commit", "runtime_manifest_sha256"],
        &[],
    )?;
    if provider.get("generation").and_then(Value::as_str) != native.provider_generation.as_deref()
        || provider
            .get("runtime_manifest_sha256")
            .and_then(Value::as_str)
            != native.runtime_manifest_sha256.as_deref()
    {
        return Err("Windows provider generation/manifest differs from native binding".into());
    }
    let terminal = sidecar.get("terminal").ok_or("terminal missing")?;
    object(
        terminal,
        &[
            "schema_version",
            "attempt_id",
            "nonce",
            "request_sha256",
            "payload",
            "process_observation",
            "restart_safety",
            "retirement_proof",
        ],
        &["policy_enforcement", "cleanup_process_creation"],
    )?;
    if number(terminal, "schema_version")? != 2
        || terminal.get("attempt_id").and_then(Value::as_str) != native.attempt_id.as_deref()
        || terminal.get("nonce").and_then(Value::as_str) != native.attempt_nonce.as_deref()
        || terminal.get("request_sha256").and_then(Value::as_str)
            != native.request_sha256.as_deref()
    {
        return Err("Windows terminal expected nonce/attempt/request differs".into());
    }
    let request_bytes = provider_request_bytes(sidecar)?;
    if native.request_sha256.as_deref() != Some(sha256(&request_bytes).as_str()) {
        return Err("captured request bytes differ from authenticated terminal hash".into());
    }
    let request = json(&request_bytes)?;
    if request.get("expected_provider_binding") != Some(provider)
        || request.get("nonce") != terminal.get("nonce")
    {
        return Err("captured request provider/nonce differs".into());
    }
    let delivery = sidecar.get("frontend_delivery").ok_or("delivery missing")?;
    object(
        delivery,
        &[
            "schema_version",
            "attempt_id",
            "nonce",
            "request_sha256",
            "authority_sha256",
            "retired_sha256",
            "retired_confirmed",
        ],
        &[],
    )?;
    if number(delivery, "schema_version")? != 1 {
        return Err("unknown frontend delivery revision".into());
    }
    for field in ["attempt_id", "nonce", "request_sha256"] {
        if delivery.get(field) != terminal.get(field) {
            return Err("frontend delivery terminal binding differs".into());
        }
    }
    for field in [
        "attempt_id",
        "request_sha256",
        "authority_sha256",
        "retired_sha256",
    ] {
        digest(text(delivery, field)?)?;
    }
    yes(delivery, &["retired_confirmed"])?;
    let proof = terminal
        .get("retirement_proof")
        .ok_or("native retirement proof missing")?;
    object(
        proof,
        &[
            "schema_version",
            "source",
            "attempt_id",
            "nonce",
            "request_sha256",
            "provider_generation",
            "launch_incarnation",
            "original_boot_id",
            "job_identity",
            "owner_manifest_sha256",
            "target_completion_observed",
            "native_job_empty_observed",
            "relay_closure_observed",
            "guardian_completion_observed",
            "owner_capabilities_closed",
            "launch_gate_closed",
            "policy_reference_bound",
        ],
        &["guardian_receipt_sha256", "current_boot_id"],
    )?;
    if number(proof, "schema_version")? != 2
        || !["live-native", "guardian-recovery", "prior-boot"].contains(&text(proof, "source")?)
    {
        return Err("unknown native retirement proof source/revision".into());
    }
    for field in ["attempt_id", "nonce", "request_sha256"] {
        if proof.get(field) != terminal.get(field) {
            return Err("nested retirement proof transaction differs".into());
        }
    }
    if proof.get("provider_generation").and_then(Value::as_str)
        != native.provider_generation.as_deref()
    {
        return Err("retirement provider generation differs".into());
    }
    validate_windows_proof_matrix(terminal)?;
    for field in ["launch_incarnation", "original_boot_id", "job_identity"] {
        if text(proof, field)?.is_empty() {
            return Err("native retirement proof omits custody identity".into());
        }
    }
    digest(text(proof, "owner_manifest_sha256")?)?;
    if text(proof, "source")? == "guardian-recovery" {
        digest(text(proof, "guardian_receipt_sha256")?)?;
    }
    if text(proof, "source")? == "prior-boot"
        && text(proof, "current_boot_id")? == text(proof, "original_boot_id")?
    {
        return Err("prior-boot proof uses current original boot".into());
    }
    let payload = terminal.get("payload").ok_or("terminal payload missing")?;
    match text(payload, "kind")? {
        "execution" => {
            object(
                payload,
                &[
                    "kind",
                    "child_pid",
                    "duration_millis",
                    "authorization_offset_millis",
                    "outcome",
                    "boundary_detail",
                ],
                &[],
            )?;
            if payload.get("child_pid").and_then(Value::as_u64) != native.root_pid.map(u64::from) {
                return Err("authenticated execution PID differs from held root".into());
            }
            validate_native_outcome(
                payload
                    .get("outcome")
                    .ok_or("native terminal outcome missing")?,
                native,
            )?;
        }
        "recovered-closure" => {
            object(
                payload,
                &[
                    "kind",
                    "primary_failure",
                    "target_creation_observed",
                    "resume_attempted",
                ],
                &[],
            )?;
            if native.origin != OutcomeOrigin::ProviderFailure {
                return Err("recovered closure replaced native target outcome".into());
            }
            validate_original_failure(
                payload
                    .get("primary_failure")
                    .ok_or("immutable original failure missing")?,
            )?;
        }
        _ => return Err("unknown Windows terminal payload authority variant".into()),
    }
    let safety = terminal
        .get("restart_safety")
        .ok_or("restart safety missing")?;
    object(
        safety,
        &[
            "direct_child_reaped",
            "workload_empty",
            "helpers_reaped",
            "containment_removed",
            "containment_incapable_of_live_members",
            "sealed_boundary_retired",
            "errors",
        ],
        &[],
    )?;
    yes(
        safety,
        &[
            "direct_child_reaped",
            "workload_empty",
            "helpers_reaped",
            "containment_removed",
            "containment_incapable_of_live_members",
            "sealed_boundary_retired",
        ],
    )?;
    empty_array(safety, "errors")?;
    let observed = terminal
        .get("process_observation")
        .ok_or("process observation missing")?;
    object(
        observed,
        &[
            "schema_version",
            "coverage",
            "root_identity",
            "final_accounting",
            "required_witness",
        ],
        &[],
    )?;
    if number(observed, "schema_version")? != 2 {
        return Err("unknown process observation revision".into());
    }
    if native.held_processes.is_empty() || native.held_processes.len() > 8192 {
        return Err("native held family omitted/exceeds bound".into());
    }
    let root = (
        native.root_pid.ok_or("held root PID missing")?,
        native.root_birth.ok_or("held root birth missing")?,
    );
    let mut held = BTreeMap::new();
    for process in &native.held_processes {
        if process.pid == 0
            || process.birth == 0
            || !process.retirement_observed
            || held.insert((process.pid, process.birth), process).is_some()
        {
            return Err("held native family is duplicate/invalid/not retired".into());
        }
    }
    if !held.contains_key(&root) {
        return Err("root identity was not independently held".into());
    }
    for process in &native.held_processes {
        let mut current = (process.pid, process.birth);
        let mut visited = BTreeSet::new();
        while current != root {
            if !visited.insert(current) || visited.len() > 64 {
                return Err("held native ancestry cycles/exceeds bound".into());
            }
            let child = held
                .get(&current)
                .ok_or("held native ancestry edge absent")?;
            let parent = (
                child.parent_pid.ok_or("descendant parent PID missing")?,
                child
                    .parent_birth
                    .ok_or("descendant parent birth missing")?,
            );
            if parent.1 > current.1 || !held.contains_key(&parent) {
                return Err("parent native identity absent/reused after child birth".into());
            }
            current = parent;
        }
    }
    let identity = |value: &Value| -> VerificationResult<(u32, u64)> {
        object(value, &["process_id", "creation_time_100ns"], &[])?;
        let pid =
            u32::try_from(number(value, "process_id")?).map_err(|_| "process PID out of bounds")?;
        let birth = number(value, "creation_time_100ns")?;
        if pid == 0 || birth == 0 {
            return Err("sample native identity absent".into());
        }
        Ok((pid, birth))
    };
    let coverage = observed.get("coverage").ok_or("coverage missing")?;
    match text(coverage, "coverage")? {
        "unavailable" => {
            object(coverage, &["coverage", "reason"], &[])?;
            let worker_loss = (key.family == "W-RETIREMENT"
                && key.scenario == "attempt-worker-loss")
                || (key.family == "C-LIFETIME" && key.scenario == "worker-loss");
            if !worker_loss
                || text(coverage, "reason")? != "worker-lost-before-freeze"
                || native.origin != OutcomeOrigin::ProviderFailure
            {
                return Err("orderly case substituted unavailable worker coverage".into());
            }
            if !observed.get("root_identity").is_none_or(Value::is_null)
                || !observed.get("final_accounting").is_none_or(Value::is_null)
                || !observed.get("required_witness").is_none_or(Value::is_null)
            {
                return Err("unavailable coverage invents root/accounting/witness".into());
            }
            return Ok(());
        }
        "sampled" => {}
        _ => return Err("unknown process coverage authority variant".into()),
    }
    object(
        coverage,
        &["coverage", "policy", "counters", "omissions", "sample"],
        &[],
    )?;
    if identity(
        observed
            .get("root_identity")
            .ok_or("observed root missing")?,
    )? != root
    {
        return Err("sample root differs from held native root".into());
    }
    let policy = coverage.get("policy").ok_or("sampling policy missing")?;
    let parameters = [
        ("snapshot_storage_bytes", 256 * 1024),
        ("sample_storage_bytes", 24 * 1024),
        ("serialized_field_bytes", 128 * 1024),
        ("snapshot_queries_per_tick", 2),
        ("identity_queries_per_tick", 64),
        ("sample_interval_millis", 100),
    ];
    object(
        policy,
        &parameters.iter().map(|p| p.0).collect::<Vec<_>>(),
        &[],
    )?;
    for (field, expected) in parameters {
        if number(policy, field)? != expected {
            return Err("native sampling policy was narrowed/replaced".into());
        }
    }
    let counters = coverage.get("counters").ok_or("sample counters missing")?;
    object(
        counters,
        &[
            "polls_attempted",
            "snapshots_obtained",
            "identity_queries_attempted",
            "identity_observations_verified",
            "vanished_or_not_member",
            "sample_evictions",
            "counter_saturated",
        ],
        &[],
    )?;
    let omissions = coverage
        .get("omissions")
        .ok_or("sample omissions missing")?;
    object(
        omissions,
        &[
            "snapshot_byte_budget",
            "snapshot_race_or_retry_budget",
            "per_tick_query_budget",
            "allocation_unavailable",
            "sample_eviction",
        ],
        &[],
    )?;
    if number(counters, "snapshots_obtained")? > number(counters, "polls_attempted")?
        || number(counters, "identity_observations_verified")?
            > number(counters, "identity_queries_attempted")?
        || number(counters, "vanished_or_not_member")?
            > number(counters, "identity_queries_attempted")?
        || number(omissions, "sample_eviction")? != number(counters, "sample_evictions")?
    {
        return Err("native sample counters/omissions contradictory".into());
    }
    let samples = coverage
        .get("sample")
        .and_then(Value::as_array)
        .ok_or("sample array missing")?;
    if samples.len() > 1024
        || samples.len() as u64 > number(counters, "identity_observations_verified")?
    {
        return Err("sample exceeds fixed native capacity/verified count".into());
    }
    let mut seen = BTreeSet::new();
    for sample in samples {
        object(sample, &["identity", "last_observation_sequence"], &[])?;
        let id = identity(sample.get("identity").ok_or("sample identity missing")?)?;
        if !held.contains_key(&id)
            || !seen.insert(id)
            || number(sample, "last_observation_sequence")? == 0
        {
            return Err("sample identity is unheld/duplicate/unstamped".into());
        }
    }
    let accounting = observed
        .get("final_accounting")
        .ok_or("final native Job accounting absent")?;
    object(
        accounting,
        &[
            "total_processes_native_u32",
            "active_processes_native_u32",
            "observed_after_target_retirement",
            "counter_regression_observed",
        ],
        &[],
    )?;
    if number(accounting, "active_processes_native_u32")? != 0
        || number(accounting, "total_processes_native_u32")? < held.len() as u64
        || accounting.get("observed_after_target_retirement") != Some(&Value::Bool(true))
        || accounting.get("counter_regression_observed") != Some(&Value::Bool(false))
    {
        return Err("native final accounting contradicts independently held family".into());
    }
    if key.family == "W-CHURN"
        && (number(counters, "sample_evictions")? == 0
            || number(accounting, "total_processes_native_u32")? < 4097)
    {
        return Err("churn did not exceed actual process sample capacity".into());
    }
    if let Some(witness) = observed.get("required_witness").filter(|v| !v.is_null()) {
        object(
            witness,
            &[
                "schema_version",
                "role",
                "child_identity",
                "attempt_id",
                "nonce",
                "request_sha256",
                "qualification_lease",
            ],
            &[],
        )?;
        if number(witness, "schema_version")? != 1
            || text(witness, "role")? != "nested-alternate-token"
            || text(witness, "qualification_lease")?.is_empty()
        {
            return Err("unknown/empty qualification witness".into());
        }
        for field in ["attempt_id", "nonce", "request_sha256"] {
            if witness.get(field) != terminal.get(field) {
                return Err("qualification witness binding differs".into());
            }
        }
        let child = identity(
            witness
                .get("child_identity")
                .ok_or("witness child missing")?,
        )?;
        if child == root || !held.contains_key(&child) {
            return Err("witness child is root/unheld".into());
        }
    }
    Ok(())
}

pub(crate) fn validate_windows_proof_matrix(terminal: &Value) -> VerificationResult<()> {
    let proof = terminal
        .get("retirement_proof")
        .ok_or("retirement proof absent")?;
    let payload = terminal.get("payload").ok_or("terminal payload absent")?;
    yes(
        proof,
        &[
            "owner_capabilities_closed",
            "launch_gate_closed",
            "policy_reference_bound",
        ],
    )?;
    let absent = |field: &str| proof.get(field).is_none_or(Value::is_null);
    let facts = [
        "target_completion_observed",
        "native_job_empty_observed",
        "relay_closure_observed",
        "guardian_completion_observed",
    ];
    for field in facts {
        if !proof.get(field).is_some_and(Value::is_boolean) {
            return Err("retirement native fact is not boolean".into());
        }
    }
    match (text(payload, "kind")?, text(proof, "source")?) {
        ("execution", "live-native") => {
            yes(proof, &facts)?;
            if !absent("guardian_receipt_sha256")
                || !absent("current_boot_id")
                || number(payload, "child_pid")? == 0
                || terminal.pointer("/process_observation/root_identity/process_id")
                    != payload.get("child_pid")
            {
                return Err("live-native proof contains recovery fields or wrong root".into());
            }
        }
        ("recovered-closure", source @ ("guardian-recovery" | "prior-boot")) => {
            let original = payload
                .get("primary_failure")
                .ok_or("recovery original failure absent")?;
            validate_original_failure(original)?;
            if original
                .pointer("/unavailable/reason")
                .and_then(Value::as_str)
                == Some("no-earlier-error-observed")
                || !terminal
                    .get("cleanup_process_creation")
                    .is_none_or(Value::is_null)
            {
                return Err("recovery proof invents creation or lacks original cause".into());
            }
            if source == "guardian-recovery" {
                yes(
                    proof,
                    &["native_job_empty_observed", "guardian_completion_observed"],
                )?;
                digest(text(proof, "guardian_receipt_sha256")?)?;
                if !absent("current_boot_id") {
                    return Err("guardian recovery contains prior-boot evidence".into());
                }
            } else {
                if facts
                    .iter()
                    .any(|field| proof.get(*field) != Some(&Value::Bool(false)))
                    || !absent("guardian_receipt_sha256")
                    || text(proof, "current_boot_id")?.is_empty()
                    || text(proof, "current_boot_id")? == text(proof, "original_boot_id")?
                {
                    return Err("prior-boot proof substitutes live native observations".into());
                }
            }
        }
        _ => return Err("retirement proof source/payload authority differs".into()),
    }
    Ok(())
}

fn validate_native_outcome(outcome: &Value, native: &NativeObservation) -> VerificationResult<()> {
    let (kind, fields): (&str, &[&str]) = match native.origin {
        OutcomeOrigin::Target | OutcomeOrigin::ApplicationRefusal => {
            ("exited", &["outcome", "child", "peak", "cleanup"])
        }
        OutcomeOrigin::Deadline => (
            "deadline-exceeded",
            &[
                "outcome",
                "deadline",
                "child_after_termination",
                "peak",
                "cleanup",
            ],
        ),
        OutcomeOrigin::Memory => (
            "limit-exceeded",
            &[
                "outcome",
                "limit",
                "observed",
                "peak",
                "evidence",
                "child_after_termination",
                "cleanup",
            ],
        ),
        OutcomeOrigin::Interrupted => (
            "interrupted",
            &["outcome", "signal", "child_after_termination", "cleanup"],
        ),
        OutcomeOrigin::ProviderFailure => (
            "monitor-failed",
            &["outcome", "error", "child_after_termination", "cleanup"],
        ),
        _ => return Err("nonexecution origin substituted into terminal execution".into()),
    };
    object(outcome, fields, &[])?;
    if text(outcome, "outcome")? != kind {
        return Err("authenticated native outcome cause differs".into());
    }
    let cleanup = outcome
        .get("cleanup")
        .ok_or("nested native cleanup missing")?;
    object(
        cleanup,
        &[
            "graceful_attempted",
            "force_attempted",
            "direct_child_reaped",
            "workload_empty",
            "errors",
        ],
        &[],
    )?;
    yes(cleanup, &["direct_child_reaped", "workload_empty"])?;
    empty_array(cleanup, "errors")?;
    if kind == "exited" {
        let child = outcome
            .get("child")
            .ok_or("native terminal child status missing")?;
        let target = native
            .target_status
            .ok_or("independent target native status missing")?;
        match text(child, "kind")? {
            "exit-code" => {
                object(child, &["kind", "code"], &[])?;
                if child.get("code").and_then(Value::as_i64) != Some(i64::from(target)) {
                    return Err("terminal native exit differs".into());
                }
            }
            "windows-status" => {
                object(child, &["kind", "status"], &[])?;
                if number(child, "status")? != u64::from(target as u32) {
                    return Err("terminal native Windows status differs".into());
                }
            }
            _ => return Err("unknown/nonexit target termination variant".into()),
        }
    }
    Ok(())
}

pub(crate) fn validate_original_failure(original: &Value) -> VerificationResult<()> {
    let variants = original
        .as_object()
        .ok_or("original failure is not a closed variant")?;
    if variants.len() != 1 {
        return Err("ambiguous original failure variant".into());
    }
    if let Some(unavailable) = variants.get("unavailable") {
        object(unavailable, &["reason"], &[])?;
        if ![
            "no-earlier-error-observed",
            "worker-lost-before-observation",
            "observation-not-durable-before-service-loss",
            "record-unavailable",
            "record-authentication-failed",
            "legacy-provider",
            "retention-expired",
        ]
        .contains(&text(unavailable, "reason")?)
        {
            return Err("unknown original failure unavailability reason".into());
        }
        return Ok(());
    }
    let observed = variants
        .get("observed")
        .ok_or("unknown original failure variant")?;
    object(observed, &["event"], &[])?;
    let event = observed.get("event").ok_or("original event missing")?;
    object(
        event,
        &[
            "sequence",
            "origin",
            "category",
            "operation",
            "code",
            "native_code",
            "observed_phase",
            "safe_detail",
            "detail_redacted",
            "detail_truncated",
            "terminalization_reference",
        ],
        &[],
    )?;
    if number(event, "sequence")? == 0 {
        return Err("original causal event sequence absent".into());
    }
    for (field, variants) in [
        (
            "origin",
            "launcher control-relay guardian-recovery startup-recovery record-writer client-transport",
        ),
        (
            "category",
            "admission launch monitor cleanup terminalization transport persistence recovery",
        ),
        (
            "operation",
            "authenticate-caller resolve-admission install-policy verify-policy start-guardian create-target verify-suspended-target authorize-target resume-target query-job-process-ids observe-process-identity accumulate-process-inventory read-job-notification query-peak-memory poll-target read-target-exit check-guardian check-desktop-authority read-control-frame terminate-job wait-job-empty retire-guardian close-final-handles build-rejection validate-terminal-response serialize-terminal-response store-record deliver-response acknowledge-terminal retire-outbox inspect-recovery-record unexpected-unwind unclassified-provider-operation query-job-accounting",
        ),
        (
            "code",
            "process-inventory-observation process-inventory-capacity job-query guardian-loss target-create target-resume target-query control-transport policy-admission policy-readback terminal-binding record-io record-authentication unexpected-provider-failure policy-revoked",
        ),
        (
            "observed_phase",
            "before-authorization authorized-before-resume resume-attempted monitoring target-exit-observed cleaning terminalizing recovery",
        ),
    ] {
        if !variants
            .split_whitespace()
            .any(|variant| Some(variant) == event.get(field).and_then(Value::as_str))
        {
            return Err("unknown original failure authority vocabulary".into());
        }
    }
    if let Some(code) = event.get("native_code").filter(|value| !value.is_null()) {
        let code = code
            .as_object()
            .ok_or("native original code is not typed")?;
        if code.len() != 1
            || code.iter().any(|(kind, value)| {
                ![
                    "win32",
                    "nt-status",
                    "h-result",
                    "winsock",
                    "errno",
                    "legacy-untyped",
                ]
                .contains(&kind.as_str())
                    || value.as_i64().is_none()
            })
        {
            return Err("unknown native original code domain/value".into());
        }
        for (kind, value) in code {
            let number = value.as_i64().ok_or("native code not integer")?;
            if if ["win32", "nt-status", "h-result"].contains(&kind.as_str()) {
                !(0..=i64::from(u32::MAX)).contains(&number)
            } else {
                !(i64::from(i32::MIN)..=i64::from(i32::MAX)).contains(&number)
            } {
                return Err("native original code exceeds its frozen native width".into());
            }
        }
    }
    let detail = event
        .get("safe_detail")
        .ok_or("safe diagnostic detail missing")?;
    if detail != "no-additional-detail" {
        let variants = detail
            .as_object()
            .ok_or("unknown safe diagnostic detail variant")?;
        if variants.len() != 1 {
            return Err("ambiguous safe diagnostic detail".into());
        }
        if let Some(counts) = variants.get("count-and-limit") {
            object(counts, &["observed", "limit"], &[])?;
            if number(counts, "observed")? > u64::from(u32::MAX)
                || number(counts, "limit")? > u64::from(u32::MAX)
            {
                return Err("diagnostic count out of bounds".into());
            }
        } else if let Some(message) = variants.get("provider-message") {
            object(message, &["id"], &[])?;
            if ![
                "original-failure-captured",
                "receipt-required-for-posttarget",
                "peer-disconnected",
                "commit-not-confirmed",
                "observation-unavailable-after-owner-loss",
            ]
            .contains(&text(message, "id")?)
            {
                return Err("unknown safe diagnostic message".into());
            }
        } else {
            return Err("unknown safe diagnostic detail authority variant".into());
        }
    }
    if !event.get("detail_redacted").is_some_and(Value::is_boolean)
        || !event.get("detail_truncated").is_some_and(Value::is_boolean)
    {
        return Err("diagnostic flags are not boolean".into());
    }
    if let Some(reference) = event
        .get("terminalization_reference")
        .filter(|value| !value.is_null())
        && reference != "first-error"
    {
        object(reference, &["secondary-error"], &[])?;
        let secondary = reference
            .get("secondary-error")
            .ok_or("unknown terminalization reference")?;
        object(secondary, &["index"], &[])?;
        if number(secondary, "index")? > u64::from(u8::MAX) {
            return Err("terminalization reference index out of bounds".into());
        }
    }
    Ok(())
}

#[expect(
    clippy::too_many_arguments,
    reason = "Keep result bytes, public request, native observation and custody as independent comparison inputs"
)]
fn validate_linux_v2(
    result: &Value,
    request_bytes: &[u8],
    native: &NativeObservation,
    key: &CaseKey,
    version: &str,
    source: &str,
    evidence: &CaseEvidence,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let invocation: NativeInvocation =
        serde_json::from_value(json(custody.bytes(&evidence.invocation)?)?)
            .map_err(|e| e.to_string())?;
    let public_invocation = json(&invocation_bytes(&invocation)?)?;
    if result.get("invocation") != Some(&public_invocation)
        || invocation_digest(&invocation)? != native.invocation_sha256
    {
        return Err(
            "mixed public parser invocation differs from persisted native invocation".into(),
        );
    }
    let public_bytes = custody.bytes(
        evidence
            .provider_request
            .as_deref()
            .ok_or("mixed actual public ingress bytes absent")?,
    )?;
    if result
        .pointer("/runtime/outcome/kind")
        .and_then(Value::as_str)
        == Some("rejected-ingress")
    {
        object(
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
            &[],
        )?;
        let runtime = result
            .get("runtime")
            .ok_or("ingress refusal runtime absent")?;
        object(
            runtime,
            &[
                "kind",
                "carrier_revision",
                "provider_contract",
                "launch_wire",
                "outcome",
            ],
            &[],
        )?;
        if text(result, "format")? != "memcordon.result"
            || number(result, "revision")? != 2
            || text(runtime, "kind")? != "linux-mixed-private"
            || number(runtime, "carrier_revision")? != 2
            || number(runtime, "provider_contract")? != 4
            || number(runtime, "launch_wire")? != 4
        {
            return Err("ingress refusal public revisions differ".into());
        }
        let tool = result.get("tool").ok_or("ingress refusal tool absent")?;
        object(
            tool,
            &["name", "version", "os", "architecture", "runtime_features"],
            &[],
        )?;
        if text(tool, "name")? != "memcordon"
            || text(tool, "version")? != version
            || text(tool, "os")? != "linux"
            || text(tool, "architecture")? != key.target.split('-').next().ok_or("target absent")?
        {
            return Err("ingress refusal selected tool differs".into());
        }
        let outcome = runtime
            .get("outcome")
            .ok_or("ingress refusal outcome absent")?;
        object(
            outcome,
            &[
                "kind",
                "request_bytes_sha256",
                "reason",
                "detail",
                "allocation",
            ],
            &[],
        )?;
        if native.origin != OutcomeOrigin::AdmissionRefusal
            || native.root_pid.is_some()
            || text(outcome, "request_bytes_sha256")? != sha256(public_bytes)
            || text(outcome, "detail")?.is_empty()
            || text(outcome, "detail")?.len() > 4096
            || ![
                "malformed-ingress",
                "recursive-provider-request",
                "unsupported-request",
            ]
            .contains(&text(outcome, "reason")?)
        {
            return Err("typed ingress refusal lacks exact noauth byte/cause binding".into());
        }
        if !matches!(
            (key.family.as_str(), key.scenario.as_str()),
            ("L-VER-01", "duplicate-request" | "unknown-request-variant")
                | ("C-ADMISSION", "unsupported-request")
        ) {
            return Err("ingress rejection substituted a different required scenario".into());
        }
        validate_request(request_bytes, key, native.origin)?;
        let actual = json(public_bytes);
        if key.scenario == "duplicate-request" {
            if !actual
                .as_ref()
                .err()
                .is_some_and(|error| error.contains("duplicate"))
            {
                return Err("duplicate ingress vector contains no actual duplicate key".into());
            }
        } else if let Ok(actual) = actual {
            let contract = actual.get("contract").unwrap_or(&actual);
            let requirements = contract
                .get("requirements")
                .and_then(Value::as_array)
                .ok_or("unsupported ingress vector lacks requirements")?;
            if !requirements.iter().any(|requirement| {
                requirement
                    .get("kind")
                    .and_then(Value::as_str)
                    .is_some_and(|kind| !known_requirement(kind, true))
            }) {
                return Err("unsupported ingress vector contains no unknown variant".into());
            }
        }
        let allocation = outcome
            .get("allocation")
            .ok_or("ingress refusal allocation absent")?;
        object(allocation, &["authorization", "obligations"], &[])?;
        if text(allocation, "authorization")? != "never-authorized" {
            return Err("ingress refusal fabricated noauth".into());
        }
        empty_array(allocation, "obligations")?;
        let frontend = result.get("frontend").ok_or("ingress frontend absent")?;
        object(
            frontend,
            &["relay_drained", "interruption", "relay_error"],
            &[],
        )?;
        if frontend.get("relay_drained") != Some(&Value::Bool(true))
            || frontend.get("interruption") != Some(&Value::Null)
            || frontend.get("relay_error") != Some(&Value::Null)
            || result.get("wrapper_status").and_then(Value::as_i64)
                != Some(i64::from(native.frontend_status))
        {
            return Err("ingress refusal frontend failed/differs".into());
        }
        return Ok(());
    }
    let public = json(public_bytes)?;
    object(
        &public,
        &[
            "format",
            "revision",
            "contract",
            "native_launch",
            "attempt_deadline_millis",
        ],
        &[],
    )?;
    if text(&public, "format")? != "memcordon.mixed-runtime-request"
        || number(&public, "revision")? != 2
        || public.get("contract") != Some(&json(request_bytes)?)
    {
        return Err("mixed actual ingress contract/revision differs".into());
    }
    let launch = public
        .get("native_launch")
        .and_then(Value::as_array)
        .ok_or("mixed actual native launch missing")?;
    let launch_bytes = launch
        .iter()
        .map(|byte| {
            byte.as_u64()
                .and_then(|value| u8::try_from(value).ok())
                .ok_or("native launch byte invalid")
        })
        .collect::<Result<Vec<_>, _>>()?;
    if launch_bytes.is_empty() {
        return Err("mixed native launch bytes empty".into());
    }
    if native.origin != OutcomeOrigin::AdmissionRefusal {
        let mut public_invocation = launch_bytes;
        public_invocation.extend(
            hex::decode(v3_request_digest(&json(request_bytes)?)?).map_err(|e| e.to_string())?,
        );
        let empty_environment = serde_json::to_vec(&NativeEnvironment::UnixBytes(Vec::new()))
            .map_err(|e| e.to_string())?;
        validate_mixed_invocation_kind(
            &public_invocation,
            request_bytes,
            custody.bytes(&evidence.input)?,
            &empty_environment,
            true,
        )?;
    }
    object(
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
        &[],
    )?;
    let frontend = result
        .get("frontend")
        .ok_or("mixed frontend evidence absent")?;
    object(
        frontend,
        &["relay_drained", "interruption", "relay_error"],
        &[],
    )?;
    if frontend.get("relay_drained") != Some(&Value::Bool(true))
        || frontend.get("relay_error") != Some(&Value::Null)
        || result.get("wrapper_status").and_then(Value::as_i64)
            != Some(i64::from(native.frontend_status))
        || (native.origin != OutcomeOrigin::Interrupted
            && frontend.get("interruption") != Some(&Value::Null))
    {
        return Err("mixed frontend drain/interruption/wrapper status differs".into());
    }
    if text(result, "format")? != "memcordon.result" || number(result, "revision")? != 2 {
        return Err("mixed public result format/revision differs".into());
    }
    let tool = result.get("tool").ok_or("tool identity missing")?;
    object(
        tool,
        &["name", "version", "os", "architecture", "runtime_features"],
        &[],
    )?;
    if text(tool, "name")? != "memcordon"
        || text(tool, "version")? != version
        || text(tool, "os")? != "linux"
        || text(tool, "architecture")? != key.target.split('-').next().ok_or("target missing")?
    {
        return Err("mixed tool/native target differs".into());
    }
    let runtime = result.get("runtime").ok_or("mixed runtime missing")?;
    object(
        runtime,
        &[
            "kind",
            "carrier_revision",
            "provider_contract",
            "launch_wire",
            "outcome",
        ],
        &[],
    )?;
    if text(runtime, "kind")? != "linux-mixed-private"
        || number(runtime, "carrier_revision")? != 2
        || number(runtime, "provider_contract")? != 4
        || number(runtime, "launch_wire")? != 4
    {
        return Err("mixed carrier/component revisions differ".into());
    }
    let outcome = runtime.get("outcome").ok_or("mixed outcome missing")?;
    match text(outcome, "kind")? {
        "indeterminate" => return Err("indeterminate mixed result cannot satisfy readiness".into()),
        "rejected-before-authorization" => {
            object(
                outcome,
                &[
                    "kind",
                    "request_sha256",
                    "request_bytes_sha256",
                    "reason",
                    "detail",
                    "allocation",
                ],
                &[],
            )?;
            if text(outcome, "detail")?.is_empty() || text(outcome, "detail")?.len() > 4096 {
                return Err("mixed rejection first-cause detail missing/unbounded".into());
            }
            if native.origin != OutcomeOrigin::AdmissionRefusal
                || native.root_pid.is_some()
                || text(outcome, "request_bytes_sha256")? != sha256(public_bytes)
            {
                return Err("mixed refusal/native request binding differs".into());
            }
            if ![
                "unauthorized-caller",
                "unauthorized-plan",
                "unauthorized-root",
                "disabled-grant",
                "wrong-grant-revision",
                "stale-epoch",
                "unauthorized-profile",
                "unauthorized-image",
                "unauthorized-identity",
                "incompatible-requirement",
                "exclusive-account-unavailable",
                "image-custody-mismatch",
                "root-custody-mismatch",
                "host-prerequisite-unavailable",
                "install-readback-failure",
                "policy-drift",
                "native-setup-failed",
                "controlled-cancellation",
            ]
            .contains(&text(outcome, "reason")?)
            {
                return Err("unknown mixed rejection authority variant".into());
            }
            if text(outcome, "request_sha256")? != v3_request_digest(&json(request_bytes)?)? {
                return Err("mixed refusal canonical semantic request differs".into());
            }
            let allocation = outcome
                .get("allocation")
                .ok_or("rejection allocation missing")?;
            object(allocation, &["authorization", "obligations"], &[])?;
            if text(allocation, "authorization")? != "never-authorized" {
                return Err("refusal does not prove never authorized".into());
            }
            empty_array(allocation, "obligations")?;
            return Ok(());
        }
        "executed" => {}
        _ => return Err("unknown mixed runtime outcome variant".into()),
    }
    object(
        outcome,
        &[
            "kind",
            "admission",
            "request_bytes_sha256",
            "provider",
            "execution",
            "retirement",
        ],
        &[],
    )?;
    if text(outcome, "request_bytes_sha256")? != sha256(public_bytes)
        || native.origin == OutcomeOrigin::AdmissionRefusal
    {
        return Err("mixed execution/request bytes differ".into());
    }
    let admission = outcome
        .get("admission")
        .ok_or("admission binding missing")?;
    object(
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
        &[],
    )?;
    let request = json(request_bytes)?;
    if text(admission, "format")? != "memcordon.private-admission-metadata"
        || number(admission, "revision")? != 2
        || admission.get("request") != Some(&request)
        || admission.get("epoch") != request.get("expected_epoch")
        || admission.get("profile_id") != request.get("authorized_profile")
        || admission.get("attempt_id").and_then(Value::as_str) != native.attempt_id.as_deref()
        || admission.get("invocation_sha256").and_then(Value::as_str)
            != native.execution_invocation_sha256.as_deref()
        || text(admission, "request_sha256")? != v3_request_digest(&request)?
    {
        return Err("mixed canonical admission/request/native invocation differs".into());
    }
    let nonce = admission
        .get("admission_nonce")
        .and_then(Value::as_array)
        .ok_or("admission nonce missing")?;
    if nonce.len() != 16
        || nonce.iter().all(|v| v.as_u64() == Some(0))
        || nonce.iter().any(|v| v.as_u64().is_none_or(|n| n > 255))
    {
        return Err("mixed admission nonce malformed/empty".into());
    }
    digest(text(admission, "registry_digest")?)?;
    let provider = outcome.get("provider").ok_or("mixed provider missing")?;
    object(
        provider,
        &["generation", "source_commit", "runtime_manifest_sha256"],
        &[],
    )?;
    if text(provider, "source_commit")? != source
        || provider.get("generation").and_then(Value::as_str)
            != native.provider_generation.as_deref()
        || provider
            .get("runtime_manifest_sha256")
            .and_then(Value::as_str)
            != native.runtime_manifest_sha256.as_deref()
    {
        return Err("mixed authenticated selected provider differs".into());
    }
    let execution = outcome
        .get("execution")
        .ok_or("mixed native execution missing")?;
    let execution_fields = [
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
    ];
    let mut execution_fields = execution_fields.to_vec();
    execution_fields.push("authorization_monotonic_millis");
    object(execution, &execution_fields, &[])?;
    if number(execution, "authorization_monotonic_millis")? == 0 {
        return Err("mixed native authorization clock absent".into());
    }
    if text(execution, "host_target")? != key.target
        || text(execution, "boot_id")?.is_empty()
        || execution.pointer("/target/pid").and_then(Value::as_u64)
            != native.root_pid.map(u64::from)
        || execution.pointer("/target/birth").and_then(Value::as_u64) != native.root_birth
        || number(execution, "caller_uid")? != number(admission, "caller_uid")?
        || number(execution, "target_uid")? == 0
        || number(execution, "target_gid")? == 0
        || number(execution, "target_uid")? == number(execution, "caller_uid")?
        || number(execution, "target_uid")? == number(execution, "init_uid")?
        || number(execution, "root_inode")? == 0
        || number(execution, "post_exec_descriptor_count")? != 3
    {
        return Err("mixed held native root/credentials/descriptor facts differ".into());
    }
    let mut identities = BTreeSet::new();
    for field in ["caller", "target", "namespace_init", "guardian"] {
        let identity = execution
            .get(field)
            .ok_or("held process identity missing")?;
        object(identity, &["pid", "birth"], &[])?;
        if number(identity, "pid")? == 0
            || number(identity, "birth")? == 0
            || !identities.insert((number(identity, "pid")?, number(identity, "birth")?))
        {
            return Err("mixed process identities absent/aliased".into());
        }
    }
    for field in [
        "user_namespace",
        "mount_namespace",
        "pid_namespace",
        "network_namespace",
        "ipc_namespace",
    ] {
        let current = execution.get(field).ok_or("namespace missing")?;
        let caller = execution
            .get(format!("caller_{field}"))
            .ok_or("caller namespace missing")?;
        object(current, &["device", "inode"], &[])?;
        object(caller, &["device", "inode"], &[])?;
        if number(current, "inode")? == 0
            || number(caller, "inode")? == 0
            || ((current == caller) != (field == "user_namespace"))
        {
            return Err("mixed namespace separation/provider user namespace differs".into());
        }
    }
    for field in [
        "runtime_image",
        "input_image",
        "root_layout",
        "execution_identity",
    ] {
        if execution.get(field) != request.get(field) {
            return Err("native mixed image/root/exclusive identity differs from request".into());
        }
    }
    yes(
        execution,
        &[
            "init_nondumpable",
            "no_new_privileges",
            "capabilities_empty",
            "target_authorized",
            "exec_observed",
        ],
    )?;
    validate_linux_prepared(outcome, execution, evidence, custody)?;
    let abi = if key.target.starts_with("x86_64-") {
        "x86_64"
    } else {
        "aarch64"
    };
    if text(execution, "filter_abi")? != abi {
        return Err("mixed native ABI differs".into());
    }
    digest(text(execution, "filter_instruction_sha256")?)?;
    let origin = match native.origin {
        OutcomeOrigin::Target | OutcomeOrigin::ApplicationRefusal => "native-exit",
        OutcomeOrigin::Deadline => "deadline",
        OutcomeOrigin::Memory => "memory-oom",
        OutcomeOrigin::Interrupted => "controlled-cancellation",
        OutcomeOrigin::ProviderFailure => text(execution, "outcome_origin")?,
        _ => return Err("mixed execution has nonexecution origin".into()),
    };
    if text(execution, "outcome_origin")? != origin
        || ![
            "native-exit",
            "native-signal",
            "deadline",
            "controlled-cancellation",
            "frontend-lost",
            "revoked",
            "memory-oom",
        ]
        .contains(&origin)
    {
        return Err("mixed native cause was relabeled".into());
    }
    if native.origin == OutcomeOrigin::Target || native.origin == OutcomeOrigin::ApplicationRefusal
    {
        let wait = execution
            .get("native_wait_status")
            .and_then(Value::as_i64)
            .ok_or("native wait status missing")?;
        if wait & 0x7f != 0 || Some(((wait >> 8) & 0xff) as i32) != native.target_status {
            return Err("mixed wait status disagrees with target exit".into());
        }
    }
    let retirement = outcome
        .get("retirement")
        .ok_or("mixed retirement missing")?;
    object(
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
        &[],
    )?;
    if retirement.get("attempt_id") != admission.get("attempt_id")
        || text(retirement, "export_receipt_sha256")?
            != custody.hash(
                evidence
                    .export_receipt
                    .as_deref()
                    .ok_or("mixed export receipt missing")?,
            )?
    {
        return Err("mixed retirement/export exact attempt binding differs".into());
    }
    yes(
        retirement,
        &[
            "workload_empty",
            "init_reaped",
            "guardian_reaped",
            "relays_drained_and_closed",
            "namespace_references_closed",
            "root_references_closed",
            "staging_removed",
            "account_quiescent",
            "reservation_retired",
        ],
    )?;
    Ok(())
}

/// Check only the completed frontend envelope; callers independently decode
/// the original outcome, request, native ownership and recovery graph.
pub(crate) fn validate_linux_public_result_envelope(
    result: &Value,
    public_invocation: &Value,
    version: &str,
    target: &str,
    native_status: i32,
    writer_pid: u32,
) -> VerificationResult<()> {
    object(
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
        &[],
    )?;
    let tool = result.get("tool").ok_or("Linux result tool absent")?;
    object(
        tool,
        &["name", "version", "os", "architecture", "runtime_features"],
        &[],
    )?;
    if !target.ends_with("linux-gnu")
        || writer_pid == 0
        || writer_pid > i32::MAX as u32
        || result["format"] != "memcordon.result"
        || result["revision"] != 2
        || result["invocation"] != *public_invocation
        || tool["name"] != "memcordon"
        || tool["version"] != version
        || tool["os"] != "linux"
        || tool["architecture"] != target.split('-').next().ok_or("Linux target absent")?
        || tool["runtime_features"] != serde_json::json!(["sealed-runtime", "private-tcp"])
        || result["wrapper_status"] != native_status
    {
        return Err("Linux original public result tool/invocation/native status differs".into());
    }
    let runtime = result.get("runtime").ok_or("Linux runtime absent")?;
    object(
        runtime,
        &[
            "kind",
            "carrier_revision",
            "provider_contract",
            "launch_wire",
            "outcome",
        ],
        &[],
    )?;
    if runtime["kind"] != "linux-mixed-private"
        || runtime["carrier_revision"] != 2
        || runtime["provider_contract"] != 4
        || runtime["launch_wire"] != 4
    {
        return Err("Linux original result carrier revisions differ".into());
    }
    let delivery = result
        .get("delivery")
        .ok_or("Linux delivery preparation absent")?;
    object(delivery, &["prepared-by"], &[])?;
    object(&delivery["prepared-by"], &["writer_pid"], &[])?;
    if delivery["prepared-by"]["writer_pid"] != writer_pid {
        return Err("Linux result delivery adopts another original writer".into());
    }
    let frontend = result
        .get("frontend")
        .ok_or("Linux frontend evidence absent")?;
    object(
        frontend,
        &["relay_drained", "interruption", "relay_error"],
        &[],
    )?;
    if frontend["relay_drained"] != true
        || !frontend["interruption"].is_null()
        || !frontend["relay_error"].is_null()
    {
        return Err("Linux completed frontend envelope lacks actual clean relay settlement".into());
    }
    Ok(())
}

fn validate_linux_prepared(
    outcome: &Value,
    execution: &Value,
    evidence: &CaseEvidence,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let path = evidence
        .prepared_observation
        .as_deref()
        .ok_or("executed mixed row omits authenticated pre-release observation")?;
    let prepared = json(custody.bytes(path)?)?;
    object(
        &prepared,
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
        &[],
    )?;
    if text(&prepared, "format")? != "memcordon.mixed-prepared-observation"
        || number(&prepared, "revision")? != 2
        || prepared.get("authorizes_launch") != Some(&Value::Bool(false))
        || prepared.get("provider") != outcome.get("provider")
        || prepared.get("admission") != outcome.get("admission")
    {
        return Err(
            "pre-release observation changed admission/provider or claims launch authority".into(),
        );
    }
    for field in [
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
    ] {
        if prepared.get(field) != execution.get(field) {
            return Err(
                "executed native identity/root differs from authenticated pre-release observation"
                    .into(),
            );
        }
    }
    let receipt = json(
        custody.bytes(
            evidence
                .prepared_native_receipt
                .as_deref()
                .ok_or("pre-release observation cannot self-certify independent native hold")?,
        )?,
    )?;
    object(
        &receipt,
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
        &[],
    )?;
    if text(&receipt, "format")? != "memcordon.linux-prepared-native-observation"
        || number(&receipt, "revision")? != 1
        || text(&receipt, "run_id")? != evidence.run_id
        || receipt.get("attempt_id") != prepared.pointer("/admission/attempt_id")
        || text(&receipt, "prepared_sha256")? != custody.hash(path)?
        || receipt.get("held_before_authorization") != Some(&Value::Bool(true))
        || receipt.get("root_device") != prepared.get("root_device")
        || receipt.get("root_inode") != prepared.get("root_inode")
    {
        return Err("native pre-release observer receipt custody/phase/root differs".into());
    }
    let observer = receipt
        .get("observer")
        .ok_or("native observer identity absent")?;
    object(observer, &["pid", "birth"], &[])?;
    if number(observer, "pid")? == 0 || number(observer, "birth")? == 0 {
        return Err("native observer process identity absent".into());
    }
    for role in ["target", "namespace_init", "guardian", "caller"] {
        let snapshot = receipt.get(role).ok_or("held native snapshot absent")?;
        object(
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
            &[],
        )?;
        let identity = prepared.get(role).ok_or("prepared process absent")?;
        if snapshot.get("process_id") != identity.get("pid")
            || snapshot.get("birth") != identity.get("birth")
            || (number(observer, "pid")?, number(observer, "birth")?)
                == (number(identity, "pid")?, number(identity, "birth")?)
        {
            return Err("independent observer native held owner differs/aliases observer".into());
        }
        let namespace_pids = snapshot
            .get("namespace_pids")
            .and_then(Value::as_array)
            .ok_or("native namespace PID tuple absent")?;
        if namespace_pids.is_empty()
            || namespace_pids.len() > 32
            || namespace_pids.first() != snapshot.get("process_id")
            || namespace_pids.iter().any(|pid| {
                pid.as_u64()
                    .is_none_or(|pid| pid == 0 || pid > u64::from(u32::MAX))
            })
            || (role == "namespace_init"
                && namespace_pids.last().and_then(Value::as_u64) != Some(1))
        {
            return Err("actual held native namespace PID tuple differs".into());
        }
        for (native_field, prepared_field) in [
            ("user", "user_namespace"),
            ("mount", "mount_namespace"),
            ("pid", "pid_namespace"),
            ("network", "network_namespace"),
            ("ipc", "ipc_namespace"),
        ] {
            let namespace = snapshot
                .get(native_field)
                .ok_or("native snapshot namespace absent")?;
            object(namespace, &["device", "inode"], &[])?;
            if number(namespace, "inode")? == 0 {
                return Err("native snapshot namespace inode absent".into());
            }
            if ["target", "namespace_init"].contains(&role)
                && Some(namespace) != prepared.get(prepared_field)
            {
                return Err("independently held native target/init namespace differs".into());
            }
            if role == "caller"
                && Some(namespace) != execution.get(format!("caller_{prepared_field}"))
            {
                return Err(
                    "native caller namespace changed between pre-release and execution".into(),
                );
            }
        }
    }
    Ok(())
}

pub(crate) fn v3_request_digest(request: &Value) -> VerificationResult<String> {
    fn length(bytes: &mut Vec<u8>, n: usize) -> VerificationResult<()> {
        bytes.extend_from_slice(
            &u16::try_from(n)
                .map_err(|_| "canonical length exceeds u16")?
                .to_be_bytes(),
        );
        Ok(())
    }
    fn string(bytes: &mut Vec<u8>, text: &str) -> VerificationResult<()> {
        length(bytes, text.len())?;
        bytes.extend_from_slice(text.as_bytes());
        Ok(())
    }
    fn hash(bytes: &mut Vec<u8>, value: &str) -> VerificationResult<()> {
        digest(value)?;
        bytes.extend_from_slice(&hex::decode(value).map_err(|e| e.to_string())?);
        Ok(())
    }
    fn bound(bytes: &mut Vec<u8>, value: &Value) -> VerificationResult<()> {
        object(value, &["id", "digest"], &[])?;
        string(bytes, text(value, "id")?)?;
        hash(bytes, text(value, "digest")?)
    }
    let mut bytes = b"memcordon.workload-contract/version3\0".to_vec();
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&3u16.to_be_bytes());
    hash(&mut bytes, text(request, "workload_plan_digest")?)?;
    let profile = request.get("authorized_profile").ok_or("profile missing")?;
    object(profile, &["id", "semantic_digest"], &[])?;
    string(&mut bytes, text(profile, "id")?)?;
    hash(&mut bytes, text(profile, "semantic_digest")?)?;
    let authorization = request
        .get("authorization")
        .ok_or("authorization missing")?;
    object(
        authorization,
        &["grant_id", "grant_revision", "approved_plan_digest"],
        &[],
    )?;
    string(&mut bytes, text(authorization, "grant_id")?)?;
    bytes.extend_from_slice(&number(authorization, "grant_revision")?.to_be_bytes());
    hash(&mut bytes, text(authorization, "approved_plan_digest")?)?;
    if request.get("ceiling").and_then(Value::as_str)
        != Some("fresh_root_ipv4_tcp_unix_streams_intra_attempt_no_gain")
    {
        return Err("unknown mixed ceiling".into());
    }
    bytes.push(1);
    let identity = request
        .get("execution_identity")
        .ok_or("exclusive identity missing")?;
    object(identity, &["identity", "exclusive_use_policy"], &[])?;
    bound(
        &mut bytes,
        identity.get("identity").ok_or("identity missing")?,
    )?;
    bound(
        &mut bytes,
        identity
            .get("exclusive_use_policy")
            .ok_or("exclusive policy missing")?,
    )?;
    for field in ["runtime_image", "input_image", "root_layout"] {
        bound(
            &mut bytes,
            request.get(field).ok_or("bound object missing")?,
        )?;
    }
    let launch = request.get("launch").ok_or("image launch missing")?;
    object(launch, &["entrypoint", "working_directory"], &[])?;
    string(&mut bytes, text(launch, "entrypoint")?)?;
    string(&mut bytes, text(launch, "working_directory")?)?;
    let epoch = request.get("expected_epoch").ok_or("epoch missing")?;
    object(epoch, &["service_instance", "revision"], &[])?;
    let nonce = epoch
        .get("service_instance")
        .and_then(Value::as_array)
        .ok_or("epoch nonce missing")?;
    if nonce.len() != 16 {
        return Err("epoch nonce length differs".into());
    }
    for value in nonce {
        bytes.push(
            u8::try_from(value.as_u64().ok_or("epoch nonce malformed")?)
                .map_err(|_| "epoch nonce malformed")?,
        );
    }
    bytes.extend_from_slice(&number(epoch, "revision")?.to_be_bytes());
    let mut requirements: Vec<_> = request
        .get("requirements")
        .and_then(Value::as_array)
        .ok_or("requirements missing")?
        .iter()
        .collect();
    requirements.sort_by_key(|value| value.get("id").and_then(Value::as_str));
    length(&mut bytes, requirements.len())?;
    for requirement in requirements {
        string(&mut bytes, text(requirement, "id")?)?;
        match text(requirement, "kind")? {
            "tcp_listener" => {
                object(requirement, &["kind", "id", "local_port", "peer"], &[])?;
                bytes.push(1);
                for (field, default, exact) in [
                    ("local_port", "kernel_assigned", "exact"),
                    (
                        "peer",
                        "dynamic_loopback_within_this_attempt",
                        "exact_loopback_endpoint",
                    ),
                ] {
                    let port = requirement.get(field).ok_or("TCP authority missing")?;
                    match text(port, "kind")? {
                        kind if kind == default => {
                            object(port, &["kind"], &[])?;
                            bytes.push(1);
                        }
                        kind if kind == exact => {
                            object(port, &["kind", "port"], &[])?;
                            let value = u16::try_from(number(port, "port")?)
                                .map_err(|_| "port out of bounds")?;
                            if value == 0 {
                                return Err("port zero is not exact port".into());
                            }
                            bytes.push(2);
                            bytes.extend_from_slice(&value.to_be_bytes());
                        }
                        _ => return Err("unknown V3 TCP scope/port variant".into()),
                    }
                }
            }
            "unix_stream_pair" | "unix_abstract_stream" | "intra_attempt_descriptor_transfer" => {
                object(requirement, &["kind", "id"], &[])?;
                bytes.push(match text(requirement, "kind")? {
                    "unix_stream_pair" => 2,
                    "unix_abstract_stream" => 4,
                    _ => 5,
                });
            }
            "unix_path_stream" | "generated_executable" => {
                object(requirement, &["kind", "id", "writable_root"], &[])?;
                bytes.push(if text(requirement, "kind")? == "unix_path_stream" {
                    3
                } else {
                    6
                });
                string(&mut bytes, text(requirement, "writable_root")?)?;
            }
            "expected_denial" => {
                object(requirement, &["kind", "id", "operation"], &[])?;
                bytes.push(7);
                let variants = [
                    "host_tcp",
                    "host_unix_path",
                    "host_unix_abstract",
                    "other_attempt",
                    "inet6",
                    "udp",
                    "raw",
                    "packet",
                    "netlink",
                    "namespace_entry",
                    "process_import",
                    "privilege_gain",
                ];
                let index = variants
                    .iter()
                    .position(|v| *v == text(requirement, "operation").unwrap_or(""))
                    .ok_or("unknown denial authority variant")?;
                bytes.push(index as u8 + 1);
            }
            _ => return Err("unknown V3 requirement authority variant".into()),
        }
    }
    if bytes.len() > 1024 * 1024 {
        return Err("canonical V3 request exceeds bound".into());
    }
    Ok(sha256(&bytes))
}

pub(crate) fn validate_mixed_invocation(
    bytes: &[u8],
    request_bytes: &[u8],
    input_bytes: &[u8],
    environment_bytes: &[u8],
) -> VerificationResult<()> {
    validate_mixed_invocation_kind(bytes, request_bytes, input_bytes, environment_bytes, false)
}

pub fn validate_mixed_public_invocation(
    bytes: &[u8],
    request_bytes: &[u8],
    input_bytes: &[u8],
    environment_bytes: &[u8],
) -> VerificationResult<()> {
    validate_mixed_invocation_kind(bytes, request_bytes, input_bytes, environment_bytes, true)
}

fn validate_mixed_invocation_kind(
    bytes: &[u8],
    request_bytes: &[u8],
    input_bytes: &[u8],
    environment_bytes: &[u8],
    public_selector: bool,
) -> VerificationResult<()> {
    let input: FixtureInput = decode(input_bytes)?;
    let NativeArguments::UnixBytes(arguments) = input.target_argv else {
        return Err("mixed argv is not Unix native bytes".into());
    };
    let NativeEnvironment::UnixBytes(environment) = decode(environment_bytes)? else {
        return Err("mixed environment has wrong native encoding".into());
    };
    validate_mixed_arguments(
        bytes,
        request_bytes,
        &arguments,
        &environment,
        input.memory_bytes,
        public_selector,
        false,
        None,
    )
}

/// Decode one original public attempt against exact retained native inputs.
pub fn validate_mixed_public_arguments(
    bytes: &[u8],
    request_bytes: &[u8],
    arguments: &[Vec<u8>],
    environment: &[UnixEnvironmentVariable],
    memory: Option<u64>,
) -> VerificationResult<()> {
    validate_mixed_arguments(
        bytes,
        request_bytes,
        arguments,
        environment,
        memory,
        true,
        true,
        None,
    )
}

pub(crate) fn validate_mixed_public_arguments_and_deadline(
    bytes: &[u8],
    request_bytes: &[u8],
    arguments: &[Vec<u8>],
    environment: &[UnixEnvironmentVariable],
    memory: Option<u64>,
    deadline: Option<u64>,
) -> VerificationResult<()> {
    validate_mixed_arguments(
        bytes,
        request_bytes,
        arguments,
        environment,
        memory,
        true,
        true,
        Some(deadline),
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "Keep result bytes, public request, native observation and custody as independent comparison inputs"
)]
fn validate_mixed_arguments(
    bytes: &[u8],
    request_bytes: &[u8],
    arguments: &[Vec<u8>],
    environment: &[UnixEnvironmentVariable],
    memory: Option<u64>,
    public_selector: bool,
    exact_public: bool,
    deadline: Option<Option<u64>>,
) -> VerificationResult<()> {
    struct Cursor<'a> {
        bytes: &'a [u8],
    }
    impl<'a> Cursor<'a> {
        fn take(&mut self, length: usize) -> VerificationResult<&'a [u8]> {
            let value = self
                .bytes
                .get(..length)
                .ok_or("truncated native invocation")?;
            self.bytes = &self.bytes[length..];
            Ok(value)
        }
        fn count(&mut self) -> VerificationResult<usize> {
            Ok(u32::from_be_bytes(
                self.take(4)?
                    .try_into()
                    .map_err(|_| "truncated native count")?,
            ) as usize)
        }
        fn value(&mut self) -> VerificationResult<&'a [u8]> {
            let length = self.count()?;
            if length > 131_072 {
                return Err("native invocation value exceeds bound".into());
            }
            self.take(length)
        }
        fn optional(&mut self) -> VerificationResult<Option<u64>> {
            match self.take(1)?[0] {
                0 => Ok(None),
                1 => Ok(Some(u64::from_be_bytes(
                    self.take(8)?
                        .try_into()
                        .map_err(|_| "native optional scalar truncated")?,
                ))),
                _ => Err("unknown native optional authority tag".into()),
            }
        }
    }
    if bytes.len() > 2 * 1024 * 1024 || bytes.len() < 32 {
        return Err("native mixed invocation byte bound differs".into());
    }
    let request = json(request_bytes)?;
    let expected = hex::decode(v3_request_digest(&request)?).map_err(|e| e.to_string())?;
    if &bytes[bytes.len() - 32..] != expected.as_slice() {
        return Err("native invocation appended V3 request binding differs".into());
    }
    let mut cursor = Cursor {
        bytes: &bytes[..bytes.len() - 32],
    };
    if cursor.take(2)? != 3u16.to_be_bytes() {
        return Err("native launch codec revision differs".into());
    }
    let restart = cursor.take(8)?;
    if exact_public && restart != 0u64.to_be_bytes() {
        return Err("single original public attempt smuggles a restart ordinal".into());
    }
    let program = cursor.value()?;
    if public_selector {
        let entrypoint = request.get("launch").ok_or("V3 launch missing")?;
        if program != text(entrypoint, "entrypoint")?.as_bytes() {
            return Err("public native image selector differs from authorized V3 id".into());
        }
    } else if !program.starts_with(b"/") || program.contains(&0) {
        return Err("native image executable is not absolute/NUL-free".into());
    }
    let count = cursor.count()?;
    if count != arguments.len() || count > 4096 {
        return Err("mixed native argv count differs from controller inputs".into());
    }
    for argument in arguments {
        if cursor.value()? != argument {
            return Err("mixed native argv bytes differ from controller inputs".into());
        }
    }
    let env_count = cursor.count()?;
    if env_count > 4096 {
        return Err("native environment exceeds bound".into());
    }
    if env_count != environment.len() {
        return Err("mixed trusted environment count differs from protected receipt".into());
    }
    let mut last_name: Option<Vec<u8>> = None;
    for expected in environment {
        let name = cursor.value()?;
        let value = cursor.value()?;
        if name.is_empty()
            || name.contains(&b'=')
            || name.contains(&0)
            || value.contains(&0)
            || last_name.as_deref().is_some_and(|last| last >= name)
        {
            return Err("native trusted startup environment is malformed/unsorted".into());
        }
        last_name = Some(name.to_vec());
        if name != expected.name || value != expected.value {
            return Err("mixed trusted environment differs from protected receipt".into());
        }
    }
    let memory_limit = cursor.optional()?;
    if (exact_public || memory.is_some()) && memory != memory_limit {
        return Err("actual native memory budget differs from independent fixture input".into());
    }
    match cursor.take(1)?[0] {
        1 => {
            cursor.take(8)?;
        }
        2 | 3 => {}
        _ => return Err("unknown swap policy authority tag".into()),
    }
    let native_deadline = cursor.optional()?;
    if deadline.is_some_and(|expected| expected != native_deadline) {
        return Err("actual native deadline budget differs from original public input".into());
    }
    let deadline_scope = cursor.take(1)?[0];
    if ![1, 2].contains(&deadline_scope) || ![1, 2].contains(&cursor.take(1)?[0]) {
        return Err("unknown native deadline/lifetime tag".into());
    }
    if deadline.is_some() && deadline_scope != 1 {
        return Err("original public attempt timer substituted supervision scope".into());
    }
    cursor.take(32)?;
    let descriptors = cursor.count()?;
    if descriptors > 64 {
        return Err("native descriptor list exceeds bound".into());
    }
    let purposes = cursor.take(descriptors)?;
    if purposes.iter().any(|tag| !(1..=8).contains(tag))
        || purposes.iter().copied().collect::<BTreeSet<_>>().len() != purposes.len()
    {
        return Err("unknown/duplicate native descriptor purpose".into());
    }
    if cursor.take(1)?[0] != 0 || !cursor.bytes.is_empty() {
        return Err("mixed invocation smuggles legacy contract/trailing bytes".into());
    }
    Ok(())
}

fn provider_request_bytes(sidecar: &Value) -> VerificationResult<Vec<u8>> {
    let values = sidecar
        .get("provider_request")
        .and_then(Value::as_array)
        .ok_or("exact provider request bytes omitted")?;
    if values.is_empty() || values.len() > 1024 * 1024 {
        return Err("provider request byte bound differs".into());
    }
    values
        .iter()
        .map(|value| {
            value
                .as_u64()
                .and_then(|v| u8::try_from(v).ok())
                .ok_or_else(|| "provider request byte is malformed".into())
        })
        .collect()
}

pub(crate) fn validate_windows_request(
    bytes: &[u8],
    workload: &[u8],
    invocation: &NativeInvocation,
    environment_bytes: &[u8],
) -> VerificationResult<()> {
    let request = json(bytes)?;
    object(
        &request,
        &[
            "restart_attempt",
            "schema_version",
            "expected_provider_binding",
            "workload_contract",
            "nonce",
            "command",
            "environment",
            "current_directory",
            "policy",
        ],
        &[],
    )?;
    if number(&request, "schema_version")? != 3
        || request.get("workload_contract") != Some(&json(workload)?)
    {
        return Err("actual Windows provider request contract/revision differs".into());
    }
    let command = request
        .get("command")
        .ok_or("native Windows command missing")?;
    object(command, &["program", "arguments"], &[])?;
    let program: Vec<u16> =
        serde_json::from_value(command.get("program").ok_or("program missing")?.clone())
            .map_err(|e| e.to_string())?;
    let args: Vec<Vec<u16>> =
        serde_json::from_value(command.get("arguments").ok_or("arguments missing")?.clone())
            .map_err(|e| e.to_string())?;
    let combined = NativeArguments::WindowsUtf16(std::iter::once(program).chain(args).collect());
    validate_arguments(&combined, "x86_64-pc-windows-msvc")?;
    if serde_json::to_value(&combined).map_err(|e| e.to_string())?
        != serde_json::to_value(&invocation.arguments).map_err(|e| e.to_string())?
    {
        return Err("actual Windows request native argv differs from invocation receipt".into());
    }
    let NativeEnvironment::WindowsUtf16(environment) = decode(environment_bytes)? else {
        return Err("Windows environment has wrong native encoding".into());
    };
    if request.get("environment")
        != Some(&serde_json::to_value(&environment).map_err(|e| e.to_string())?)
    {
        return Err("actual Windows request environment differs from protected receipt".into());
    }
    let mut names = BTreeSet::new();
    if environment.len() > 4096 {
        return Err("Windows environment exceeds bound".into());
    }
    for variable in &environment {
        let key: Vec<_> = variable
            .name
            .iter()
            .map(|unit| {
                if (u16::from(b'a')..=u16::from(b'z')).contains(unit) {
                    *unit - 32
                } else {
                    *unit
                }
            })
            .collect();
        if variable.name.is_empty()
            || variable.name.contains(&0)
            || variable.value.contains(&0)
            || !names.insert(key)
        {
            return Err("actual Windows environment is malformed/ambiguous".into());
        }
    }
    let directory: Vec<u16> = serde_json::from_value(
        request
            .get("current_directory")
            .ok_or("native cwd missing")?
            .clone(),
    )
    .map_err(|e| e.to_string())?;
    if directory.is_empty() || directory.contains(&0) || directory.len() > 32_768 {
        return Err("actual native Windows cwd is malformed".into());
    }
    let policy = request
        .get("policy")
        .ok_or("native Windows launch policy missing")?;
    object(
        policy,
        &[
            "memory_limit_bytes",
            "absolute_deadline_millis",
            "lifetime",
            "poll_interval_millis",
            "signal_grace_millis",
            "command_exit_grace_millis",
            "limit_grace_millis",
        ],
        &[],
    )?;
    if !["command", "workload"].contains(&text(policy, "lifetime")?)
        || number(policy, "poll_interval_millis")? == 0
    {
        return Err("unknown/invalid actual Windows launch policy".into());
    }
    Ok(())
}

pub(crate) fn semantic_expectations(
    key: &CaseKey,
    native: &NativeObservation,
    semantic: &SemanticObservation,
    input: &FixtureInput,
    operations: &BTreeSet<&str>,
    roles: &BTreeSet<&str>,
    custody: &custody::Custody,
) -> VerificationResult<()> {
    let require_ops = |required: &[&str]| -> VerificationResult<()> {
        if required.iter().any(|op| !operations.contains(op)) {
            return Err(format!("required native operations missing: {required:?}"));
        }
        Ok(())
    };
    let require_roles = |required: &[&str]| -> VerificationResult<()> {
        if required.iter().any(|role| !roles.contains(role)) {
            return Err(format!("independent byte products missing: {required:?}"));
        }
        Ok(())
    };
    let completed = || -> VerificationResult<()> {
        if native.origin != OutcomeOrigin::Target
            || native.target_status != Some(0)
            || native.frontend_status != 0
        {
            return Err("positive case did not complete naturally with native zero".into());
        }
        Ok(())
    };
    let counter = |name: &str| {
        semantic
            .counters
            .get(name)
            .copied()
            .ok_or_else(|| format!("native counter omitted: {name}"))
    };
    if ["C-PACKAGE", "W-PACKAGE", "W-UPGRADE"].contains(&key.family.as_str()) {
        if key.family == "W-UPGRADE" && key.scenario == "fresh-positive" {
            completed()?;
            require_ops(&["fresh-admission"])?;
        } else {
            if native.origin != OutcomeOrigin::PackageOperation || native.frontend_status != 0 {
                return Err("package operation failed or was not run".into());
            }
            require_ops(&[&format!("package-{}", key.scenario)])?;
        }
        return Ok(());
    }
    if ["C-STATUS", "W-STATUS", "L-LIFE-03"].contains(&key.family.as_str())
        || key.family == "W-POPULATION"
    {
        let scenario = key.scenario.as_str();
        match scenario {
            "deadline" | "held-257-deadline" => {
                if native.origin != OutcomeOrigin::Deadline
                    || input.deadline_millis.is_none_or(|v| v == 0)
                {
                    return Err("deadline case lacks actual deadline origin/budget".into());
                }
                require_ops(&["deadline-expired"])?;
                if scenario == "held-257-deadline" && counter("held-population")? < 257 {
                    return Err("population pressure was narrowed below root plus 256".into());
                }
            }
            "memory" => {
                if native.origin != OutcomeOrigin::Memory
                    || input.memory_bytes.is_none_or(|v| v == 0)
                {
                    return Err("memory case lacks confirmed native limit/budget".into());
                }
                require_ops(&["memory-limit-confirmed"])?;
            }
            "cancellation" => {
                if native.origin != OutcomeOrigin::Interrupted {
                    return Err("cancellation lost native interruption origin".into());
                }
                require_ops(&["controlled-cancellation"])?;
            }
            "admission-refusal" => {
                admission_refusal(native)?;
                require_ops(&["admission-refused"])?;
            }
            "target-failure" | "nonzero" => {
                if native.origin != OutcomeOrigin::Target
                    || native.target_status.is_none_or(|v| v == 0)
                {
                    return Err("nonzero target case substituted wrapper/provider failure".into());
                }
            }
            "reserved-target-exit" => {
                if native.origin != OutcomeOrigin::Target
                    || !native
                        .target_status
                        .is_some_and(|v| (123..=127).contains(&v))
                {
                    return Err("reserved target exit origin/status differs".into());
                }
            }
            "zero" => completed()?,
            "exit-123" | "exit-124" | "exit-125" | "exit-126" | "exit-127" => {
                let expected = scenario
                    .strip_prefix("exit-")
                    .ok_or("invalid status scenario")?
                    .parse::<i32>()
                    .map_err(|e| e.to_string())?;
                if native.origin != OutcomeOrigin::Target
                    || native.target_status != Some(expected)
                    || native.frontend_status != expected
                {
                    return Err("reserved target exit was relabeled or status differs".into());
                }
            }
            _ => return Err("unknown status semantic anchor".into()),
        }
        return Ok(());
    }
    if key.family == "C-ADMISSION"
        || key.family == "L-ID-02"
        || key.family == "L-VER-01"
        || key.family == "W-BINDING"
    {
        if key.scenario == "positive" {
            completed()?;
            require_ops(&["admission-granted"])?;
        } else {
            admission_refusal(native)?;
            require_ops(&["admission-refused"])?;
            negative_probe(semantic, native, "admission")?;
        }
        return Ok(());
    }
    if key.family == "C-PARSER" {
        completed()?;
        require_ops(&["strict-current-result-decoded"])?;
        return Ok(());
    }
    if key.family == "L-MIX-02" || (key.family == "W-JOINT" && key.scenario == "endpoint-mismatch")
    {
        if native.origin != OutcomeOrigin::ApplicationRefusal
            || native.target_status != Some(42)
            || native.application_stage.as_deref() != Some("endpoint-policy")
        {
            return Err("endpoint mismatch never reached typed application refusal".into());
        }
        require_ops(&[
            "tcp-owned-listener",
            "second-reserved-listener",
            "application-endpoint-refusal",
        ])?;
        negative_probe(semantic, native, "application")?;
        return Ok(());
    }
    if key.family == "L-MIX-01" {
        completed()?;
        require_ops(&[
            "tcp-owned-listener",
            "tcp-conflicting-bind",
            "http-exchange",
            "unix-path-exchange",
            "unix-abstract-exchange",
            "unix-stream-pair",
            "scm-rights-listener",
            "scm-rights-private-file",
            "locked-rust-compile",
            "compiled-tests",
            "generated-executable",
        ])?;
        require_roles(&[
            "tcp",
            "http",
            "unix-path",
            "unix-abstract",
            "unix-pair",
            "transferred-file",
            "compiled-child",
        ])?;
        if input
            .toolchain_identity
            .as_deref()
            .is_none_or(str::is_empty)
        {
            return Err("joint build lacks locked compiler/linker observation".into());
        }
        return Ok(());
    }
    if key.family == "L-MIX-03" {
        completed()?;
        require_ops(&["scm-rights-listener", "scm-rights-private-file"])?;
        require_roles(&["tcp", "transferred-file"])?;
        return Ok(());
    }
    if key.family == "L-MIX-04" {
        if key.scenario == "cooperation" {
            completed()?;
            require_ops(&["same-attempt-cooperation"])?;
            require_roles(&["cooperation"])?;
        } else {
            completed()?;
            require_ops(&["cross-attempt-denial"])?;
            negative_probe(semantic, native, "linux")?;
        }
        return Ok(());
    }
    if key.family == "W-JOINT" {
        completed()?;
        require_ops(&[
            "tcp-owned-listener",
            "tcp-conflicting-bind",
            "http-exchange",
            "named-pipe-exchange",
            "allowed-file-write",
            "generated-descendant",
        ])?;
        require_roles(&["tcp", "http", "named-pipe", "file", "descendant"])?;
        if key.scenario == "restricted" {
            require_ops(&["restricted-token", "protected-write-denied"])?;
        }
        return Ok(());
    }
    if key.family == "W-TOOLCHAIN" || key.family == "L-IMG-03" {
        completed()?;
        require_ops(&[
            "locked-rust-compile",
            "compiled-tests",
            "generated-executable",
        ])?;
        require_roles(&["compiled-child"])?;
        if input
            .toolchain_identity
            .as_deref()
            .is_none_or(str::is_empty)
        {
            return Err("compile omitted locked compiler/linker identity".into());
        }
        if key.family == "W-TOOLCHAIN" {
            require_ops(&["compiled-dll-loaded"])?;
            require_roles(&["dll-empty", "dll-binary"])?;
        }
        if key.scenario == "image-only-entrypoint" {
            require_ops(&["host-entrypoint-absent", "image-entrypoint-executed"])?;
        }
        return Ok(());
    }
    if key.family == "W-ENVELOPE" {
        completed()?;
        require_ops(&[
            "caller-token-attested",
            "creation-job-attested",
            "suspended-target-attested",
            "native-handle-list-attested",
        ])?;
        if key.scenario == "restricted" {
            require_ops(&[
                "restricted-token",
                "allowed-file-write",
                "protected-write-denied",
            ])?;
        }
        if key.scenario == "sentinel-handles" {
            require_ops(&["frontend-sentinel-held", "sentinel-not-inherited"])?;
        }
        return Ok(());
    }
    if ["C-IO", "W-IO", "L-MIX-05"].contains(&key.family.as_str()) {
        if key.scenario == "argv-nul-rejection" {
            admission_refusal(native)?;
            require_ops(&["argv-nul-rejected"])?;
            return Ok(());
        }
        completed()?;
        match key.scenario.as_str() {
            "empty-input" => {
                if !input.binary.is_empty() {
                    return Err("empty input vector was changed".into());
                }
                require_roles(&["stdout", "stderr"])?;
            }
            "empty-message" => {
                if !input.binary.is_empty() {
                    return Err("empty message vector was changed".into());
                }
                require_ops(&["empty-message-exchanged"])?;
                require_roles(&["message"])?;
            }
            "empty-stdout-stderr" => {
                require_roles(&["stdout", "stderr"])?;
                for comparison in &semantic.comparisons {
                    if ["stdout", "stderr"].contains(&comparison.role.as_str())
                        && !custody.bytes(&comparison.actual)?.is_empty()
                    {
                        return Err("empty stream contains bytes".into());
                    }
                }
            }
            "empty-file" => {
                require_roles(&["file"])?;
                if !input.binary.is_empty() {
                    return Err("empty file vector differs".into());
                }
            }
            "binary-file" => {
                byte_vector(&input.binary, "all-bytes")?;
                require_roles(&["file"])?;
            }
            "binary-streams" | "all-bytes" => {
                byte_vector(&input.binary, "all-bytes")?;
                require_roles(&["stdout", "stderr"])?;
            }
            "embedded-nul" | "invalid-utf8" | "final-fragment" => {
                byte_vector(&input.binary, &key.scenario)?;
                require_roles(&["stdout", "stderr"])?;
            }
            "bounded-large-output" | "backpressure-separated-streams" => {
                require_roles(&["stdout", "stderr"])?;
                if key.target.ends_with("linux-gnu") && key.scenario == "bounded-large-output" {
                    require_ops(&["stdout-bytes", "stderr-bytes"])?;
                } else {
                    require_ops(&["backpressure-observed"])?;
                }
                if counter("stdout-bytes")? < 1024 * 1024 || counter("stderr-bytes")? < 1024 * 1024
                {
                    return Err("large separated output case narrowed".into());
                }
            }
            "native-argv" | "argv-empty" | "argv-whitespace" | "argv-quotes"
            | "argv-backslashes" | "argv-unicode" | "argv-path" => {
                require_roles(&["native-argv"])?;
                argv_vector(&input.target_argv, &key.scenario)?;
                let comparison = semantic
                    .comparisons
                    .iter()
                    .find(|c| c.role == "native-argv")
                    .ok_or("argv comparison missing")?;
                let actual: NativeArguments = decode(custody.bytes(&comparison.actual)?)?;
                if serde_json::to_value(actual).map_err(|e| e.to_string())?
                    != serde_json::to_value(&input.target_argv).map_err(|e| e.to_string())?
                {
                    return Err("native target argv does not match exact input vector".into());
                }
            }
            _ => return Err("unknown exact I/O semantic anchor".into()),
        }
        return Ok(());
    }
    if key.family == "W-CHURN" {
        completed()?;
        require_ops(&["held-cohort-ancestry", "sample-eviction-attested"])?;
        if counter("churn-creations")? < 4096
            || counter("churn-completions")? < 4096
            || counter("churn-generations")? < 3
            || counter("max-live-children")? == 0
            || counter("max-live-children")? > 64
            || counter("evicted-completions")? == 0
        {
            return Err("churn/depth/cohort/sample-eviction obligations incomplete".into());
        }
        return Ok(());
    }
    if key.family.starts_with("L-ISO-")
        || key.family == "L-IMG-01"
        || key.family == "L-IMG-02"
        || key.family == "L-IMG-04"
    {
        if key.scenario == "own-abstract-positive" {
            completed()?;
            require_ops(&["unix-abstract-exchange"])?;
            require_roles(&["unix-abstract"])?;
        } else {
            completed()?;
            require_ops(&["native-authority-probe"])?;
            negative_probe(semantic, native, "linux")?;
        }
        return Ok(());
    }
    if key.family == "L-ID-01" {
        completed()?;
        require_ops(&[
            "final-credentials-attested",
            "generated-descendant-credentials-attested",
        ])?;
        return Ok(());
    }
    if key.family == "L-ID-03" {
        require_ops(&[&format!("policy-{}", key.scenario)])?;
        if ["revoke-discovery", "revoke-preparation", "revoke-release"]
            .contains(&key.scenario.as_str())
        {
            admission_refusal(native)?;
        } else if key.scenario == "revoke-running" {
            if ![OutcomeOrigin::Interrupted, OutcomeOrigin::ProviderFailure]
                .contains(&native.origin)
            {
                return Err("live revoke did not terminate the admitted target".into());
            }
        } else {
            completed()?;
        }
        return Ok(());
    }
    if key.family == "W-DESCENDANT"
        || key.family == "L-LIFE-01"
        || (key.family == "C-LIFETIME" && key.scenario == "root-first")
    {
        completed()?;
        require_ops(&["held-descendant-identity", "descendant-natural-completion"])?;
        require_roles(&["descendant"])?;
        match key.scenario.as_str() {
            "root-first" | "root-first-resource-descendant" => {
                require_ops(&["root-exited-before-held-descendant"])?
            }
            "intermediate-parent-first" => {
                require_ops(&["intermediate-exited-before-held-descendant"])?
            }
            "nested-job" => require_ops(&["nested-job-contained"])?,
            "breakaway-denial" => require_ops(&["breakaway-denied"])?,
            "allowed-token-change" => require_ops(&["allowed-token-change-contained"])?,
            _ => return Err("unknown descendant semantic anchor".into()),
        }
        return Ok(());
    }
    if key.family == "W-CAPACITY" {
        completed()?;
        require_ops(&[&format!("capacity-{}", key.scenario), "fresh-admission"])?;
        return Ok(());
    }
    if key.family == "C-LIFETIME"
        || key.family == "L-LIFE-02"
        || key.family == "L-LIFE-05"
        || ["W-CAUSAL", "W-GUARDIAN", "W-REPLAY", "W-RETIREMENT"].contains(&key.family.as_str())
    {
        if ["natural", "output-backpressure", "relay-backpressure"].contains(&key.scenario.as_str())
        {
            completed()?;
        } else if ["recovery", "public-recovery-after-loss"].contains(&key.scenario.as_str()) {
            require_ops(&["native-recovery", "fresh-admission"])?;
        } else if native.origin != OutcomeOrigin::ProviderFailure {
            return Err("fault case lost original provider failure origin".into());
        }
        require_ops(&[
            &format!("fault-{}", key.scenario),
            "original-cause-retained",
            "independent-retirement",
        ])?;
        return Ok(());
    }
    Err("case has no independently implemented semantic acceptance".into())
}

fn admission_refusal(native: &NativeObservation) -> VerificationResult<()> {
    if native.origin != OutcomeOrigin::AdmissionRefusal
        || native.root_pid.is_some()
        || native.target_status.is_some()
    {
        return Err("provider refusal was substituted by target/wrapper failure".into());
    }
    Ok(())
}

fn negative_probe(
    semantic: &SemanticObservation,
    native: &NativeObservation,
    domain: &str,
) -> VerificationResult<()> {
    let probe = semantic
        .negative_probe
        .as_ref()
        .ok_or("negative row lacks native denial observation")?;
    if probe.stage != semantic.key.scenario || probe.domain != domain || probe.native_code == 0 {
        return Err("negative probe stage/domain/code differs".into());
    }
    let host_tcp = semantic.key.family == "L-ISO-01" && semantic.key.scenario == "host-tcp";
    let protocol_denial = semantic.key.family == "L-ISO-01"
        && ["udp", "raw"].contains(&semantic.key.scenario.as_str());
    if domain == "linux"
        && ![1, 2, 9, 13, 18, 20, 22, 30, 38, 40, 95, 97, 111].contains(&probe.native_code)
        && !(host_tcp && [101, 113].contains(&probe.native_code))
        && !(protocol_denial && probe.native_code == 93)
    {
        return Err("unexpected Linux denial errno".into());
    }
    if domain == "application"
        && (probe.native_code != 42
            || native.application_stage.as_deref() != Some("endpoint-policy"))
    {
        return Err("application denial has wrong typed stage/status".into());
    }
    Ok(())
}

fn byte_vector(bytes: &[u8], scenario: &str) -> VerificationResult<()> {
    let valid = match scenario {
        "all-bytes" => bytes == (0..=255).collect::<Vec<u8>>(),
        "embedded-nul" => {
            bytes.len() >= 3 && bytes.contains(&0) && bytes.iter().any(|byte| *byte != 0)
        }
        "invalid-utf8" => std::str::from_utf8(bytes).is_err(),
        "final-fragment" => !bytes.is_empty() && !bytes.ends_with(b"\n"),
        _ => false,
    };
    if !valid {
        return Err("frozen byte vector was narrowed/substituted".into());
    }
    Ok(())
}

fn argv_vector(args: &NativeArguments, scenario: &str) -> VerificationResult<()> {
    let values: Vec<Vec<u32>> = match args {
        NativeArguments::UnixBytes(values) => values
            .iter()
            .map(|v| v.iter().map(|c| u32::from(*c)).collect())
            .collect(),
        NativeArguments::WindowsUtf16(values) => values
            .iter()
            .map(|v| v.iter().map(|c| u32::from(*c)).collect())
            .collect(),
    };
    let has = |byte: u32| values.iter().any(|value| value.contains(&byte));
    let valid = match scenario {
        "native-argv" => {
            values.iter().any(Vec::is_empty)
                && has(u32::from(b' '))
                && has(u32::from(b'"'))
                && has(u32::from(b'\\'))
                && values.iter().flatten().any(|c| *c > 127)
        }
        "argv-empty" => values.iter().any(Vec::is_empty),
        "argv-whitespace" => has(u32::from(b' ')) || has(u32::from(b'\t')),
        "argv-quotes" => has(u32::from(b'"')),
        "argv-backslashes" => has(u32::from(b'\\')),
        "argv-unicode" => values.iter().flatten().any(|c| *c > 127),
        "argv-path" => has(u32::from(b'\\')) || has(u32::from(b'/')),
        _ => false,
    };
    if !valid {
        return Err("native argv vector omits its required semantic case".into());
    }
    Ok(())
}
