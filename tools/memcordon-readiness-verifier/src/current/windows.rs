//! Independent checks of current Windows request, native, and lifetime evidence.
use super::{CaseEvidenceV2, ProductObservationV2};
use crate::{ComponentBuild, EvidenceClass, VerificationResult};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};

type Resolver<'a> = &'a dyn Fn(&str) -> VerificationResult<Vec<u8>>;
#[path = "windows_resources.rs"]
mod resources;
pub use resources::special_resource_digest;

pub fn terminal_retired_digest(response: &Value) -> VerificationResult<String> {
    struct Ordered<'a> {
        value: &'a Value,
        fields: &'a [&'a str],
    }
    impl Serialize for Ordered<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeMap;
            let mut map = serializer.serialize_map(Some(self.fields.len()))?;
            for field in self.fields {
                let value = self
                    .value
                    .get(*field)
                    .ok_or_else(|| serde::ser::Error::custom("native retired wire field absent"))?;
                map.serialize_entry(field, value)?;
            }
            map.end()
        }
    }
    if response["kind"] != "terminal-retired-v2"
        || response.get("preauthorization_retirement_proof").is_some()
    {
        return Err("posttarget retired wire variant differs".into());
    }
    let bytes = serde_json::to_vec(&Ordered {
        value: response,
        fields: &[
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
    })
    .map_err(|error| error.to_string())?;
    Ok(crate::sha256(&bytes))
}

pub(super) fn terminal_proof_digest(authority: &str) -> VerificationResult<String> {
    type Raw = std::collections::BTreeMap<String, Box<serde_json::value::RawValue>>;
    let get = |object: &Raw, key: &str| {
        object
            .get(key)
            .map(|value| value.get().to_owned())
            .ok_or_else(|| format!("actual native authority {key} absent"))
    };
    let root: Raw = serde_json::from_str(authority).map_err(|error| error.to_string())?;
    let kind: Value =
        serde_json::from_str(&get(&root, "kind")?).map_err(|error| error.to_string())?;
    let proof = if kind == "terminal" {
        get(&root, "retirement_proof")?
    } else if kind == "reject" {
        let rejection: Raw =
            serde_json::from_str(&get(&root, "rejection")?).map_err(|error| error.to_string())?;
        let disposition: Raw = serde_json::from_str(&get(&rejection, "disposition")?)
            .map_err(|error| error.to_string())?;
        let receipt: Raw = serde_json::from_str(&get(&disposition, "receipt")?)
            .map_err(|error| error.to_string())?;
        get(&receipt, "retirement_proof")?
    } else {
        return Err("native authority has no actual terminal proof".into());
    };
    Ok(crate::sha256(proof.as_bytes()))
}

fn document(path: &str, resolve: Resolver<'_>) -> VerificationResult<Value> {
    crate::custody::validate_path(path)?;
    crate::validate_json_document(&resolve(path)?)
}
fn fields(value: &Value, required: &[&str], optional: &[&str]) -> VerificationResult<()> {
    let object = value.as_object().ok_or("current Windows object absent")?;
    if required.iter().any(|key| !object.contains_key(*key))
        || object
            .keys()
            .any(|key| !required.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    {
        return Err("current Windows object fields differ".into());
    }
    Ok(())
}
fn header(value: &Value, format: &str, revision: u64) -> VerificationResult<()> {
    if value["format"] != format || value["revision"] != revision {
        return Err("current Windows format/revision differs".into());
    }
    Ok(())
}
fn yes(value: &Value, names: &[&str]) -> VerificationResult<()> {
    if names.iter().any(|name| value[*name] != true) {
        return Err("current native Windows observation is incomplete".into());
    }
    Ok(())
}
fn digest(value: &Value) -> VerificationResult<&str> {
    let value = value.as_str().ok_or("current digest absent")?;
    if value.len() != sha2::Sha256::output_size() * 2
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("current digest is malformed".into());
    }
    Ok(value)
}
fn provider(product: &ProductObservationV2, resolve: Resolver<'_>) -> VerificationResult<Value> {
    let bytes = resolve(&product.runtime_manifest)?;
    let manifest = crate::validate_json_document(&bytes)?;
    header(&manifest, "memcordon.runtime-manifest", 2)?;
    if manifest["source_commit"] != product.source_commit
        || manifest["version"] != product.version
        || manifest["target"] != product.key.target
        || product.runtime_profile != "windows-sealed-current-token-v1"
    {
        return Err("current Windows selected runtime differs".into());
    }
    Ok(
        json!({"generation":format!("{}:{}",product.version,product.source_commit),"source_commit":product.source_commit,"runtime_manifest_sha256":crate::sha256(&bytes)}),
    )
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Request {
    format: String,
    revision: u32,
    runtime: WindowsRuntime,
    requirements: Vec<Value>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WindowsRuntime {
    kind: String,
    profile: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Invocation {
    syntax: String,
    budget_tokens: Vec<InvocationBudget>,
    memory_token: Option<String>,
    deadline_token: Option<String>,
    argv: Vec<Argument>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct InvocationBudget {
    kind: String,
    token: String,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Argument {
    display: String,
    raw: Option<ArgumentRaw>,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ArgumentRaw {
    encoding: String,
    data: String,
}

pub(super) fn request(bytes: &[u8]) -> VerificationResult<(Value, String)> {
    let value = crate::validate_json_document(bytes)?;
    let request: Request =
        serde_json::from_value(value.clone()).map_err(|error| error.to_string())?;
    if request.format != "memcordon.workload-request"
        || request.revision != 1
        || request.runtime.kind != "windows-sealed"
        || request.runtime.profile != "windows-sealed-current-token-v1"
        || !request.requirements.is_empty()
    {
        return Err("current Windows request profile differs".into());
    }
    Ok((
        value,
        crate::sha256(&serde_json::to_vec(&request).map_err(|error| error.to_string())?),
    ))
}

fn guardian(value: &Value, expected: &Value, agent_hash: &str) -> VerificationResult<()> {
    header(value, "memcordon.windows-native-guardian-quiescence", 1)?;
    if value["image_sha256"] != agent_hash
        || value["runtime_manifest_sha256"] != expected["runtime_manifest_sha256"]
    {
        return Err("guardian query belongs to another installed runtime".into());
    }
    let slots = value["slots"]
        .as_array()
        .ok_or("native guardian slots absent")?;
    if slots.len() != 8 {
        return Err("native guardian slot inventory differs".into());
    }
    let mut names = BTreeSet::new();
    for slot in slots {
        let name = slot["service_name"]
            .as_str()
            .ok_or("native guardian service name absent")?;
        if !names.insert(name) || slot["current_state"] != 1 || slot["process_id"] != 0 {
            return Err("actual guardian service has not stopped".into());
        }
        digest(&slot["configuration_sha256"])?;
        let config = &slot["configuration"];
        let mut hash = sha2::Sha256::new();
        for field in ["service_type", "start_type", "error_control"] {
            let number = u32::try_from(
                config[field]
                    .as_u64()
                    .ok_or("native guardian config number absent")?,
            )
            .map_err(|error| error.to_string())?;
            hash.update(number.to_le_bytes());
        }
        for field in ["binary_path_utf16", "service_start_name_utf16"] {
            let units: Vec<u16> =
                serde_json::from_value(config[field].clone()).map_err(|error| error.to_string())?;
            if units.len() > 32768 || units.contains(&0) {
                return Err("native guardian configuration string differs".into());
            }
            hash.update((units.len() as u64).to_le_bytes());
            for unit in units {
                hash.update(unit.to_le_bytes());
            }
        }
        if hex::encode(hash.finalize()) != digest(&slot["configuration_sha256"])? {
            return Err("actual guardian config digest differs".into());
        }
    }
    if names
        != (0..8)
            .map(|index| format!("MemCordonSealedGuardian-{index:03}"))
            .collect::<BTreeSet<_>>()
            .iter()
            .map(String::as_str)
            .collect()
    {
        return Err("actual guardian slot names differ".into());
    }
    Ok(())
}

/// The common layer has already checked the actual selected bytes and outer
/// lifetime journal. This joins the native query and removal observations.
pub fn verify_lifecycle(
    product: &ProductObservationV2,
    resolve: Resolver<'_>,
) -> VerificationResult<()> {
    let expected = provider(product, resolve)?;
    let agent = product
        .components
        .iter()
        .find(|component| component.role == "sealed-agent")
        .ok_or("selected Windows agent absent")?;
    let required = BTreeSet::from([
        super::NativeResourceV2::WindowsJob,
        super::NativeResourceV2::WindowsTarget,
        super::NativeResourceV2::WindowsRelays,
        super::NativeResourceV2::WindowsControlHandles,
        super::NativeResourceV2::WindowsDesktop,
        super::NativeResourceV2::WindowsProcessHandles,
    ]);
    let actual = product
        .lifecycle
        .native
        .iter()
        .map(|entry| entry.resource)
        .collect::<BTreeSet<_>>();
    if actual != required
        || actual.len() != product.lifecycle.native.len()
        || product.lifecycle.native.iter().any(|entry| !entry.settled)
    {
        return Err("current Windows native lifetime obligations differ".into());
    }
    for path in product
        .lifecycle
        .native
        .iter()
        .map(|entry| entry.evidence.as_str())
        .collect::<BTreeSet<_>>()
    {
        let value = document(path, resolve)?;
        header(&value, "memcordon.windows-installed-finalization", 2)?;
        if value["lease_id"] != product.lifecycle.lease_id
            || value["product"]
                != serde_json::to_value(&product.key).map_err(|error| error.to_string())?
            || value["provider"] != expected
        {
            return Err("native finalization belongs to another installed lifetime".into());
        }
        let recovery = &value["recovery"];
        if recovery["recovery"] != json!({"Ok":null})
            || recovery["native_quiescence"] != json!({"Ok":null})
            || recovery["native_status"] != 0
            || recovery["deadline_exhausted"] != false
        {
            return Err("native recovery did not actually complete".into());
        }
        let mut captures = BTreeMap::new();
        for artifact in recovery["artifacts"]
            .as_array()
            .ok_or("native finalization captures absent")?
        {
            let path = artifact["path"]
                .as_str()
                .ok_or("native capture path absent")?;
            let bytes = resolve(path)?;
            if crate::sha256(&bytes) != digest(&artifact["sha256"])? {
                return Err("native finalization raw capture digest differs".into());
            }
            let name = path
                .rsplit('/')
                .next()
                .ok_or("native capture basename absent")?;
            if captures.insert(name, bytes).is_some() {
                return Err("native finalization capture is duplicated".into());
            }
        }
        let inventory = crate::validate_json_document(
            captures
                .get("recovery.stdout.bin")
                .ok_or("actual native recovery inventory absent")?,
        )?;
        if inventory["schema_version"] != 1
            || inventory["provider_generation"] != expected["generation"]
            || inventory["challenge"].as_str().is_none_or(str::is_empty)
            || inventory["current_boot_identity"]
                .as_str()
                .is_none_or(str::is_empty)
        {
            return Err("actual native inventory generation differs".into());
        }
        for counter in [
            "executing",
            "incomplete_proof",
            "unacknowledged_outboxes",
            "ack_retirement_in_progress",
            "active_admissions",
            "quarantined",
        ] {
            if inventory[counter] != 0 {
                return Err("actual native inventory retains an owner".into());
            }
        }
        let query = crate::validate_json_document(
            captures
                .get("guardian-quiescence.json")
                .ok_or("actual guardian query absent")?,
        )?;
        guardian(&query, &expected, &agent.installed_sha256)?;
        let removal = &value["removal"];
        let removal_bytes = resolve(
            removal["path"]
                .as_str()
                .ok_or("actual package removal receipt absent")?,
        )?;
        if crate::sha256(&removal_bytes) != digest(&removal["sha256"])? {
            return Err("actual removal receipt digest differs".into());
        }
        let removal = crate::validate_json_document(&removal_bytes)?;
        header(&removal, "memcordon.windows-native-removal", 2)?;
        if removal["provider_generation"] != expected["generation"] {
            return Err("removed runtime generation differs".into());
        }
        yes(
            &removal,
            &[
                "fixture_processes_absent",
                "installed_image_processes_absent",
            ],
        )?;
        let services = removal["service_observations"]
            .as_array()
            .ok_or("actual SCM removal observations absent")?;
        if services.len() != 11 {
            return Err("actual SCM removal inventory differs".into());
        }
        let mut service_names = BTreeSet::new();
        for service in services {
            if service["api"] != "OpenServiceW"
                || service["native_domain"] != "win32"
                || service["native_code"] != 1060
                || !service_names.insert(
                    service["service_name"]
                        .as_str()
                        .ok_or("removed service name absent")?,
                )
            {
                return Err("service removal was not actually observed".into());
            }
        }
        let mut expected_services = (0..8)
            .map(|index| format!("MemCordonSealedGuardian-{index:03}"))
            .collect::<BTreeSet<_>>();
        expected_services.extend(
            [
                "MemCordonSealedControl",
                "MemCordonSealedLauncher",
                "MemCordonSealedSessionBroker",
            ]
            .map(str::to_owned),
        );
        if service_names != expected_services.iter().map(String::as_str).collect() {
            return Err("actual removed service names differ".into());
        }
        let census = &removal["native_component_census"];
        if census["api"] != "CreateToolhelp32Snapshot/Process32FirstW/Process32NextW"
            || census["terminal_native_code"] != 18
            || census["matching_processes"] != json!([])
            || census["required_image_names_utf16"]
                .as_array()
                .is_none_or(|names| names.len() != 3)
        {
            return Err("actual package process census differs".into());
        }
        if removal["path_observations"]
            .as_array()
            .is_none_or(Vec::is_empty)
        {
            return Err("actual removed path observations absent".into());
        }
    }
    Ok(())
}

fn bytes_json(value: &Value) -> VerificationResult<Vec<u8>> {
    serde_json::from_value(value.clone()).map_err(|error| error.to_string())
}

pub(super) fn result(value: &Value) -> VerificationResult<()> {
    header(value, "memcordon.result", 3)?;
    fields(
        value,
        &[
            "format",
            "revision",
            "tool",
            "invocation",
            "request",
            "provider",
            "workload_attempt",
            "release",
            "outcome",
            "cleanup",
            "delivery",
            "output_delivery",
            "diagnostics",
            "provider_failure",
            "request_rejection",
            "windows_rejection",
            "windows_attempt",
            "runtime",
        ],
        &[],
    )?;
    if !value["workload_attempt"].is_null() || !value["output_delivery"].is_null() {
        return Err("Windows result imports another runtime's owners".into());
    }
    if !value["provider_failure"].is_null() {
        super::windows_diagnostics::validate_projection(&value["provider_failure"])?;
        if value["provider_failure"]["provider_binding"] != value["provider"] {
            return Err("Windows diagnostic projection differs from actual result provider".into());
        }
    }
    Ok(())
}

fn positive(
    evidence: &CaseEvidenceV2,
    input: &Value,
    product: &ProductObservationV2,
    resolve: Resolver<'_>,
) -> VerificationResult<()> {
    if !positive_key(&evidence.key) {
        return Err("current Windows case requires its own native semantic oracle".into());
    }
    positive_scope(evidence, input, product, resolve, None)
}

fn positive_key(key: &crate::CaseKey) -> bool {
    let scenarios: &[&str] = match key.family.as_str() {
        "C-IO" => &[
            "empty-input",
            "empty-message",
            "binary-streams",
            "binary-file",
            "native-argv",
            "bounded-large-output",
        ],
        "C-ADMISSION" => &["positive"],
        "W-BINDING" => &["effective-caller-token", "restricted-token-preserved"],
        "W-ENVELOPE" => &["ordinary", "restricted", "sentinel-handles"],
        "W-JOINT" => &["ordinary", "restricted", "endpoint-mismatch"],
        "W-TOOLCHAIN" => &["ordinary", "restricted"],
        "W-IO" => &[
            "empty-stdout-stderr",
            "empty-message",
            "embedded-nul",
            "all-bytes",
            "invalid-utf8",
            "final-fragment",
            "backpressure-separated-streams",
            "empty-file",
            "binary-file",
            "argv-empty",
            "argv-whitespace",
            "argv-quotes",
            "argv-backslashes",
            "argv-unicode",
            "argv-path",
        ],
        "W-CHURN" => &["natural-4096-three-generations"],
        "W-DESCENDANT" => &[
            "root-first",
            "intermediate-parent-first",
            "nested-job",
            "breakaway-denial",
            "allowed-token-change",
        ],
        "W-STATUS" => &[
            "zero",
            "nonzero",
            "exit-123",
            "exit-124",
            "exit-125",
            "exit-126",
            "exit-127",
            "target-failure",
            "deadline",
            "memory",
        ],
        "C-STATUS" => &[
            "zero", "nonzero", "exit-123", "exit-124", "exit-125", "exit-126", "exit-127",
            "deadline", "memory",
        ],
        "C-PARSER" => &["valid-current-result"],
        "C-LIFETIME" => &["root-first"],
        "W-RETIREMENT" => &["natural", "output-backpressure"],
        "W-UPGRADE" => &["fresh-positive"],
        _ => &[],
    };
    scenarios.contains(&key.scenario.as_str())
}

fn positive_scope(
    evidence: &CaseEvidenceV2,
    input: &Value,
    product: &ProductObservationV2,
    resolve: Resolver<'_>,
    overlap: Option<&crate::behavior::CapacityOverlap>,
) -> VerificationResult<()> {
    let expected = provider(product, resolve)?;
    let request_bytes = resolve(
        evidence
            .request
            .as_deref()
            .ok_or("current Windows request bytes absent")?,
    )?;
    let (declared, request_hash) = request(&request_bytes)?;
    let public = document(
        evidence
            .raw_result
            .as_deref()
            .ok_or("current Windows result absent")?,
        resolve,
    )?;
    result(&public)?;
    if public["provider"] != expected
        || public["release"] != "released"
        || public["runtime"]["kind"] != "windows-sealed"
        || public["runtime"]["profile"] != "windows-sealed-current-token-v1"
        || public["request"]["request_sha256"] != request_hash
        || public["cleanup"]["state"] != "complete"
    {
        return Err(
            "current Windows positive result belongs to another request/runtime or is incomplete"
                .into(),
        );
    }
    let native = &public["runtime"]["native"];
    if native["schema_version"] != 3
        || native["credential_transition_disposition"] != "preserve-caller-envelope"
    {
        return Err("current native credential disposition differs".into());
    }
    yes(
        native,
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
    let sidecar = document(
        evidence
            .authenticated_terminal
            .as_deref()
            .ok_or("actual authenticated terminal absent")?,
        resolve,
    )?;
    header(&sidecar, "memcordon.windows-terminal-observation", 2)?;
    fields(
        &sidecar,
        &[
            "format",
            "revision",
            "provider",
            "terminal",
            "frontend_delivery",
            "provider_request",
            "terminal_authority_json",
        ],
        &[],
    )?;
    if sidecar["provider"] != expected {
        return Err("authenticated terminal provider differs".into());
    }
    let terminal = &sidecar["terminal"];
    validate_terminal_authority(
        terminal,
        sidecar["terminal_authority_json"]
            .as_str()
            .ok_or("actual immutable native authority bytes absent")?,
        &sidecar["frontend_delivery"],
    )?;
    if terminal["schema_version"] != 3 || terminal["payload"]["kind"] != "execution" {
        return Err("positive terminal does not contain current native execution".into());
    }
    let launch_bytes = bytes_json(&sidecar["provider_request"])?;
    if launch_bytes.len() > 1024 * 1024
        || crate::sha256(&launch_bytes) != digest(&terminal["request_sha256"])?
    {
        return Err("original native launch bytes differ".into());
    }
    let launch = crate::validate_json_document(&launch_bytes)?;
    super::windows_actors::validate_launch_request(&launch)?;
    if launch["schema_version"] != 4
        || launch["workload_request"] != declared
        || launch["expected_provider_binding"] != expected
        || launch["nonce"] != terminal["nonce"]
    {
        return Err("current native launch differs from ordinary request".into());
    }
    let invocation: crate::NativeInvocation =
        serde_json::from_value(document(&evidence.invocation, resolve)?)
            .map_err(|error| error.to_string())?;
    let reported: Invocation =
        serde_json::from_value(public["invocation"].clone()).map_err(|error| error.to_string())?;
    if reported.syntax != "plus-budgets-v1"
        || crate::sha256(&serde_json::to_vec(&reported).map_err(|error| error.to_string())?)
            != crate::reconstruct_invocation_sha256(&invocation)?
    {
        return Err("current result invocation differs from captured original native argv".into());
    }
    let crate::NativeArguments::WindowsUtf16(argv) = &invocation.arguments else {
        return Err("current Windows invocation substitutes byte argv".into());
    };
    if argv.is_empty()
        || launch["command"]["program"] != json!(argv[0])
        || launch["command"]["arguments"] != json!(argv[1..])
    {
        return Err("native provider launch substituted target argv".into());
    }
    if launch["policy"]["memory_limit_bytes"] != input["memory_bytes"]
        || launch["policy"]["absolute_deadline_millis"]
            .as_u64()
            .is_none_or(|deadline| deadline == 0)
    {
        return Err(
            "native Windows resource request differs from actual finite fixture limits".into(),
        );
    }
    let association = json!({"provider":expected,"attempt_id":terminal["attempt_id"],"request_sha256":terminal["request_sha256"]});
    if public["windows_attempt"] != association
        || native["frontend_provider_association"] != association
    {
        return Err("current result substituted native attempt".into());
    }
    let proof = &terminal["retirement_proof"];
    if proof["schema_version"] != 3
        || proof["source"] != "live-native"
        || proof["provider_generation"] != expected["generation"]
        || native["retirement"] != *proof
    {
        return Err("current native retirement source differs".into());
    }
    yes(
        proof,
        &[
            "target_completion_observed",
            "native_job_empty_observed",
            "relay_closure_observed",
            "guardian_completion_observed",
            "owner_capabilities_closed",
            "launch_gate_closed",
        ],
    )?;
    for field in ["attempt_id", "nonce", "request_sha256"] {
        if proof[field] != terminal[field]
            || sidecar["frontend_delivery"][field] != terminal[field]
            || native["frontend_delivery"][field] != terminal[field]
        {
            return Err("native terminal/retirement/delivery binding differs".into());
        }
    }
    yes(&sidecar["frontend_delivery"], &["acknowledgement_observed"])?;
    yes(
        &native["frontend_delivery"],
        &["terminal_validated", "acknowledgement_observed"],
    )?;
    if native["frontend_delivery"]["terminal_sha256"]
        != sidecar["frontend_delivery"]["terminal_sha256"]
        || native["frontend_delivery"]["retired_sha256"]
            != sidecar["frontend_delivery"]["retired_sha256"]
    {
        return Err("current delivery hashes differ".into());
    }
    let mut boundary = terminal["payload"]["boundary_detail"].clone();
    if boundary["mechanism"] != "windows-job-object-v3" {
        return Err("current terminal nested native revision differs".into());
    }
    boundary
        .as_object_mut()
        .ok_or("native terminal object absent")?
        .remove("mechanism");
    let mut projection = native.clone();
    for field in [
        "frontend_delivery",
        "frontend_provider_association",
        "retirement",
    ] {
        projection
            .as_object_mut()
            .ok_or("native result absent")?
            .remove(field);
        boundary
            .as_object_mut()
            .ok_or("terminal native absent")?
            .remove(field);
    }
    if projection != boundary
        || native["target_identity"] != terminal["process_observation"]["root_identity"]
        || native["process_observation"] != terminal["process_observation"]
    {
        return Err("current result native facts differ from actual terminal".into());
    }
    let obligations = public["cleanup"]["obligations"]
        .as_array()
        .ok_or("current cleanup obligations absent")?;
    let mut resources = BTreeSet::new();
    for obligation in obligations {
        if obligation["settled"] != true
            || !resources.insert(
                obligation["resource"]
                    .as_str()
                    .ok_or("cleanup resource absent")?,
            )
        {
            return Err("current cleanup is forged or duplicated".into());
        }
    }
    if resources != BTreeSet::from(["target", "aggregate", "job", "guardian", "relays", "record"]) {
        return Err("current Windows cleanup obligation inventory differs".into());
    }
    let semantic: crate::SemanticObservation =
        serde_json::from_value(document(&evidence.semantic_observation, resolve)?)
            .map_err(|error| error.to_string())?;
    let observed: crate::NativeObservation =
        serde_json::from_value(document(&evidence.native_observation, resolve)?)
            .map_err(|error| error.to_string())?;
    let fixture: crate::FixtureInput =
        serde_json::from_value(input.clone()).map_err(|error| error.to_string())?;
    if semantic.key != evidence.key
        || observed.run_id != evidence.run_id
        || observed.lease_id != evidence.lease_id
        || observed.attempt_id.as_deref() != terminal["attempt_id"].as_str()
        || observed.request_sha256.as_deref() != terminal["request_sha256"].as_str()
        || observed.root_pid.map(u64::from) != native["target_identity"]["process_id"].as_u64()
        || observed.root_birth != native["target_identity"]["creation_time_100ns"].as_u64()
    {
        return Err("current independent target observation differs".into());
    }
    if observed.invocation_sha256 != invocation.association_sha256
        || public["outcome"]["wrapper_status"] != observed.frontend_status
    {
        return Err("actual frontend status/invocation differs from result".into());
    }
    if !(observed.authenticated_provider_exchange
        && observed.relay_complete
        && observed.result_named_identity_verified
        && observed.result_readback_verified)
    {
        return Err("current result delivery was not independently observed".into());
    }
    let status_case = matches!(evidence.key.family.as_str(), "W-STATUS" | "C-STATUS");
    let wanted = if status_case && evidence.key.scenario == "deadline" {
        "deadline"
    } else if status_case && evidence.key.scenario == "memory" {
        "confirmed-memory-limit"
    } else {
        "completed"
    };
    if public["outcome"]["kind"] != wanted {
        return Err("actual target outcome does not satisfy current Windows case".into());
    }
    let run = &terminal["payload"]["outcome"];
    let direct = if run["outcome"] == "exited" {
        &run["child"]
    } else {
        &run["child_after_termination"]
    };
    if public["outcome"]["native_termination"] != *direct {
        return Err("current target termination differs from actual native wait".into());
    }
    if wanted == "completed" {
        let expected_status =
            if evidence.key.family == "W-JOINT" && evidence.key.scenario == "endpoint-mismatch" {
                42
            } else if status_case {
                match evidence.key.scenario.as_str() {
                    "nonzero" | "target-failure" => 17,
                    "exit-123" => 123,
                    "exit-124" => 124,
                    "exit-125" => 125,
                    "exit-126" => 126,
                    "exit-127" => 127,
                    _ => 0,
                }
            } else {
                0
            };
        if run["outcome"] != "exited"
            || !((direct["kind"] == "exit-code" && direct["code"] == expected_status)
                || (direct["kind"] == "windows-status" && direct["status"] == expected_status))
        {
            return Err("exact target application status differs".into());
        }
    } else if (wanted == "deadline" && run["outcome"] != "deadline-exceeded")
        || (wanted == "confirmed-memory-limit" && run["outcome"] != "limit-exceeded")
    {
        return Err("current resource outcome lacks actual native resource termination".into());
    }
    let mut values = BTreeMap::new();
    let behavior = semantic
        .fixture_behavior
        .as_ref()
        .ok_or("current raw fixture behavior absent")?;
    let mut paths = BTreeSet::from([
        behavior.descriptor.clone(),
        behavior.transcript.clone(),
        semantic.challenge.clone(),
        evidence.invocation.clone(),
        evidence.stdout.clone(),
        evidence.stderr.clone(),
    ]);
    paths.extend(behavior.expected_token.iter().cloned());
    paths.extend(
        behavior
            .peer_artifacts
            .iter()
            .map(|artifact| artifact.path.clone()),
    );
    paths.extend(behavior.native_binding.iter().cloned());
    let mut total = 0usize;
    while let Some(path) = paths.pop_first() {
        if values.contains_key(&path) {
            continue;
        }
        let bytes = resolve(&path)?;
        total = total
            .checked_add(bytes.len())
            .ok_or("current behavior evidence bytes overflow")?;
        if total as u64 > crate::MAX_PRODUCER_BYTES || values.len() >= crate::MAX_PRODUCER_ARTIFACTS
        {
            return Err("current behavior evidence exceeds bound".into());
        }
        if let Ok(value) = crate::validate_json_document(&bytes) {
            collect_references(&value, &mut paths);
        }
        values.insert(path, bytes);
    }
    let custody = crate::custody::Custody::from_verified_values(values)?;
    if evidence.key.family == "C-IO" {
        common_io(evidence, &fixture, behavior, &observed, &custody)?;
    }
    if evidence.key.family == "W-RETIREMENT" && evidence.key.scenario == "output-backpressure" {
        super::byte_effects::verify_raw_streams(
            "bounded-large-output",
            &(u8::MIN..=u8::MAX).collect::<Vec<_>>(),
            custody.bytes(&evidence.stdout)?,
            custody.bytes(&evidence.stderr)?,
        )?;
    }
    let facts = if let Some(overlap) = overlap {
        crate::behavior::validate_capacity_overlap(
            behavior, &semantic, &observed, &fixture, &custody, overlap,
        )?
    } else {
        crate::behavior::validate(behavior, &semantic, &observed, &fixture, &custody)?
    };
    let retirement: crate::RetirementObservation =
        crate::wire::decode(&resolve(&evidence.retirement)?)?;
    super::windows_facts::verify_retirement(&retirement, &observed, overlap.is_some())?;
    for operation in &semantic.operations {
        if !facts.operations.contains(&operation.operation) {
            return Err("current requested behavioral fact lacks actual native operation".into());
        }
    }
    for (counter, count) in &semantic.counters {
        if facts.counters.get(counter) != Some(count) {
            return Err("current behavioral counter differs from actual native events".into());
        }
    }
    Ok(())
}

fn common_io(
    evidence: &CaseEvidenceV2,
    input: &crate::FixtureInput,
    behavior: &crate::FixtureBehavior,
    native: &crate::NativeObservation,
    custody: &crate::custody::Custody,
) -> VerificationResult<()> {
    let descriptor: Value = crate::wire::decode(custody.bytes(&behavior.descriptor)?)?;
    let peer = |role: &str| -> VerificationResult<&[u8]> {
        let paths = behavior
            .peer_artifacts
            .iter()
            .filter(|artifact| artifact.role == role)
            .collect::<Vec<_>>();
        if paths.len() != 1 {
            return Err(format!("current raw {role} product absent or duplicated"));
        }
        custody.bytes(&paths[0].path)
    };
    let stdout = custody.bytes(&evidence.stdout)?;
    let stderr = custody.bytes(&evidence.stderr)?;
    match evidence.key.scenario.as_str() {
        "empty-input" => {
            if descriptor["case"] != "empty-input" || !peer("actual-stdin")?.is_empty() {
                return Err("empty-input target did not retain actual empty stdin readback".into());
            }
            super::byte_effects::verify_raw_streams("empty-input", &input.binary, stdout, stderr)?;
            let mut tail = custody.bytes(&behavior.transcript)?;
            let mut found = 0usize;
            while !tail.is_empty() {
                let width = std::mem::size_of::<u32>();
                let prefix = tail
                    .get(..width)
                    .ok_or("truncated actual stdin transcript header")?;
                let length = usize::try_from(u32::from_le_bytes(
                    prefix
                        .try_into()
                        .map_err(|_| "actual stdin transcript prefix width")?,
                ))
                .map_err(|error| error.to_string())?;
                let end = width
                    .checked_add(length)
                    .ok_or("actual stdin transcript size overflow")?;
                let row: Value = crate::wire::decode(
                    tail.get(width..end)
                        .ok_or("actual stdin transcript event truncated")?,
                )?;
                if row["stage"] == "stdin-read-to-eof" {
                    let bytes: Vec<u8> = serde_json::from_value(row["value"].clone())
                        .map_err(|error| error.to_string())?;
                    if !bytes.is_empty() || row["pid"].as_u64() != native.root_pid.map(u64::from) {
                        return Err(
                            "stdin EOF read came from another native target or consumed bytes"
                                .into(),
                        );
                    }
                    found = found
                        .checked_add(1)
                        .ok_or("stdin observation count overflow")?;
                }
                tail = &tail[end..];
            }
            if found != 1 {
                return Err("actual target stdin EOF event absent or duplicated".into());
            }
        }
        "empty-message" => {
            if descriptor["case"] != "joint" || !input.binary.is_empty() {
                return Err(
                    "common empty-message substitutes a nonempty input or another fixture".into(),
                );
            }
        }
        "binary-streams" | "bounded-large-output" => {
            if descriptor["case"] != "binary-streams" {
                return Err("raw binary stream case uses another fixture operation".into());
            }
            super::byte_effects::verify_raw_streams(
                &evidence.key.scenario,
                &(u8::MIN..=u8::MAX).collect::<Vec<_>>(),
                stdout,
                stderr,
            )?;
        }
        "binary-file" => {
            if descriptor["case"] != "binary-files" {
                return Err("binary file case uses another fixture operation".into());
            }
            super::byte_effects::verify_binary_file(&input.binary, peer("binary-file")?)?;
        }
        "native-argv" => {
            if descriptor["case"] != "native-argv" {
                return Err("native argv case uses another fixture operation".into());
            }
            let actual: crate::NativeArguments = crate::wire::decode(peer("native-argv")?)?;
            super::byte_effects::verify_native_argv(&input.target_argv, &actual, "native-argv")?;
        }
        _ => return Err("unknown current common Windows IO effect".into()),
    }
    Ok(())
}

fn collect_references(value: &Value, paths: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if matches!(key.as_str(), "artifact" | "path")
                    && let Some(path) = value.as_str()
                    && crate::custody::validate_path(path).is_ok()
                {
                    paths.insert(path.into());
                }
                collect_references(value, paths);
            }
        }
        Value::Array(values) => {
            for value in values {
                collect_references(value, paths);
            }
        }
        _ => {}
    }
}

pub fn validate_terminal_authority(
    terminal: &Value,
    bytes: &str,
    delivery: &Value,
) -> VerificationResult<()> {
    fields(
        delivery,
        &[
            "attempt_id",
            "nonce",
            "request_sha256",
            "terminal_sha256",
            "retired_sha256",
            "terminal_validated",
            "acknowledgement_observed",
        ],
        &[],
    )?;
    let raw: &serde_json::value::RawValue =
        serde_json::from_str(bytes).map_err(|error| error.to_string())?;
    let value = crate::validate_json_document(raw.get().as_bytes())?;
    let actual = if value["kind"] == "terminal" {
        let mut receipt = value.clone();
        receipt
            .as_object_mut()
            .ok_or("actual terminal wire object absent")?
            .remove("kind");
        receipt
    } else if value["kind"] == "reject" {
        value["rejection"]["disposition"]["receipt"].clone()
    } else {
        return Err("immutable native authority has another protocol variant".into());
    };
    if actual != *terminal || crate::sha256(bytes.as_bytes()) != delivery["terminal_sha256"] {
        return Err(
            "retained native terminal bytes differ from exact acknowledged authority digest".into(),
        );
    }
    if delivery["terminal_validated"] != true || delivery["acknowledgement_observed"] != true {
        return Err("actual terminal ACK retirement absent".into());
    }
    for field in ["attempt_id", "nonce", "request_sha256"] {
        if delivery[field] != terminal[field] {
            return Err("actual terminal ACK crosses native transaction".into());
        }
    }
    for field in ["terminal_sha256", "retired_sha256"] {
        crate::digest(delivery[field].as_str().ok_or("native ACK digest absent")?)?;
    }
    Ok(())
}

pub fn verify_case(
    evidence: &CaseEvidenceV2,
    input: &Value,
    product: Option<&ProductObservationV2>,
    component_build: Option<&ComponentBuild>,
    version: &str,
    repository: Option<&str>,
    resolve: Resolver<'_>,
) -> VerificationResult<()> {
    if !evidence.key.target.ends_with("windows-msvc") {
        return Err("current Windows verifier received another target".into());
    }
    if evidence.key.evidence_class == EvidenceClass::InstalledProduct {
        let product = product.ok_or("current selected Windows product absent")?;
        if component_build.is_some() {
            return Err("installed Windows case substitutes a component build".into());
        }
        if evidence.key.family == "C-CANCEL" && evidence.key.scenario == "before-preparation" {
            return current_preallocation_cancel(evidence, input, product, resolve);
        }
        if evidence.key.family == "C-CANCEL"
            && evidence.key.scenario == "service-restart-fresh-request"
        {
            return current_service_restart(evidence, input, product, resolve);
        }
        if (evidence.key.family == "C-CANCEL"
            && ["held-before-release", "after-release", "during-drain"]
                .contains(&evidence.key.scenario.as_str()))
            || (evidence.key.family == "C-OWNER"
                && [
                    "request-substitution",
                    "foreign-inspect",
                    "foreign-cancel",
                    "foreign-recover",
                    "stale-attempt",
                ]
                .contains(&evidence.key.scenario.as_str()))
        {
            return current_held_cancel(evidence, input, product, resolve);
        }
        if ["C-PACKAGE", "W-PACKAGE", "C-INSTALL-CURRENT"].contains(&evidence.key.family.as_str())
            || (evidence.key.family == "W-UPGRADE"
                && ["upgrade", "verify", "uninstall", "recover"]
                    .contains(&evidence.key.scenario.as_str()))
        {
            return package_case(evidence, input, product, resolve);
        }
        if matches!(
            (evidence.key.family.as_str(), evidence.key.scenario.as_str()),
            ("W-POPULATION", "held-257-deadline")
                | ("W-GUARDIAN", "after-release")
                | ("W-CAUSAL", "known-guardian-original")
                | ("C-LIFETIME", "guardian-loss")
        ) {
            return special_case(evidence, input, product, resolve);
        }
        let semantic = document(&evidence.semantic_observation, resolve)?;
        if semantic["format"] == "memcordon.windows-refusal-observation" {
            return refusal(evidence, product, &semantic, resolve);
        }
        if (evidence.key.family == "W-RETIREMENT"
            && [
                "frontend-loss",
                "control-service-loss",
                "attempt-worker-loss",
            ]
            .contains(&evidence.key.scenario.as_str()))
            || (evidence.key.family == "C-LIFETIME"
                && ["frontend-loss", "service-loss", "worker-loss", "recovery"]
                    .contains(&evidence.key.scenario.as_str()))
            || (evidence.key.family == "W-REPLAY"
                && evidence.key.scenario == "public-recovery-after-loss")
        {
            return loss(evidence, product, resolve);
        }
        if evidence.key.family == "W-CAPACITY" {
            return capacity(evidence, product, resolve);
        }
        return positive(evidence, input, product, resolve);
    }
    let build = component_build.ok_or("current native Windows build absent")?;
    if product.is_some()
        || build.source_commit != evidence.source_commit
        || build.source_tree_sha256 != evidence.source_tree_sha256
    {
        return Err("current component source/build association differs".into());
    }
    if evidence.key.family == "C-PARSER" {
        return super::parsers::verify_case(evidence, input, build, version, resolve);
    }
    let semantic: crate::SemanticObservation =
        crate::wire::decode(&resolve(&evidence.semantic_observation)?)?;
    if let Some(actors) = &semantic.component_actors {
        let invocation: crate::NativeInvocation =
            crate::wire::decode(&resolve(&evidence.invocation)?)?;
        let native: crate::NativeObservation =
            crate::wire::decode(&resolve(&evidence.native_observation)?)?;
        let retirement: crate::RetirementObservation =
            crate::wire::decode(&resolve(&evidence.retirement)?)?;
        let mut paths = BTreeSet::from([
            evidence.input.clone(),
            semantic.challenge.clone(),
            build.executable.clone(),
        ]);
        paths.extend(build.actor_executable.iter().cloned());
        paths.extend(build.frontend_wrapper_executable.iter().cloned());
        for actor in actors {
            let value = serde_json::to_value(actor).map_err(|error| error.to_string())?;
            let object = value.as_object().ok_or("current actor object absent")?;
            for (key, value) in object {
                if ["recipe_id", "selection_kind"].contains(&key.as_str()) {
                    continue;
                }
                if let Some(path) = value.as_str() {
                    paths.insert(path.into());
                }
                if key == "extinction_recovery"
                    && let Some(fields) = value.as_object()
                {
                    for path in fields.values() {
                        paths.insert(
                            path.as_str()
                                .ok_or("current extinction path absent")?
                                .into(),
                        );
                    }
                }
            }
        }
        let mut values = BTreeMap::new();
        let mut total = 0usize;
        for path in paths {
            crate::custody::validate_path(&path)?;
            let bytes = resolve(&path)?;
            total = total
                .checked_add(bytes.len())
                .ok_or("current actor evidence byte overflow")?;
            if total as u64 > crate::MAX_PRODUCER_BYTES
                || values.len() >= crate::MAX_PRODUCER_ARTIFACTS
            {
                return Err("current actor evidence exceeds bound".into());
            }
            values.insert(path, bytes);
        }
        let custody = crate::custody::Custody::from_verified_values(values)?;
        let context = super::windows_actors::WindowsAcceptanceContext {
            evidence,
            invocation: &invocation,
            native: &native,
            retirement: &retirement,
            semantic: &semantic,
            build,
            custody: &custody,
            version,
            repository,
        };
        if super::windows_actors::validate(&context)? {
            return Ok(());
        }
        return Err("current actor oracle did not recognize native case".into());
    }
    if semantic.component_test.is_some() {
        return component(evidence, input, build, &semantic, resolve);
    }
    Err("current Windows component lacks independently joined current native wire and semantic observations".into())
}

fn special_case(
    evidence: &CaseEvidenceV2,
    input: &Value,
    product: &ProductObservationV2,
    resolve: Resolver<'_>,
) -> VerificationResult<()> {
    let population = evidence.key.family == "W-POPULATION";
    let case = if population {
        "sampling-population"
    } else if evidence.key.family == "C-LIFETIME" {
        "guardian-loss-lifetime"
    } else {
        "guardian-loss-after-release"
    };
    let mode = if population {
        "windows-inventory-capacity"
    } else {
        "windows-guardian-loss-hold"
    };
    header(input, "memcordon.windows-installed-special-case", 1)?;
    fields(
        input,
        &[
            "format",
            "revision",
            "key",
            "run_id",
            "source_commit",
            "source_tree_sha256",
            "lease_id",
            "case",
            "artifacts",
        ],
        &[],
    )?;
    if input["key"] != serde_json::to_value(&evidence.key).map_err(|error| error.to_string())?
        || input["case"] != case
        || input["run_id"] != evidence.run_id
        || input["source_commit"] != product.source_commit
        || input["source_tree_sha256"] != product.source_tree_sha256
        || input["lease_id"] != product.lifecycle.lease_id
        || evidence.lease_id.as_deref() != Some(&product.lifecycle.lease_id)
        || evidence.component_recipe_id.is_some()
        || evidence.recovery.is_some()
    {
        return Err("installed special case source/lease/operation differs".into());
    }
    let path = |role: &str| {
        input["artifacts"][role]
            .as_str()
            .ok_or_else(|| format!("special actual {role} artifact absent"))
    };
    for (role, actual) in [
        ("result", evidence.raw_result.as_deref()),
        ("request", evidence.request.as_deref()),
        ("terminal", evidence.authenticated_terminal.as_deref()),
        ("invocation", Some(evidence.invocation.as_str())),
        ("stdout", Some(evidence.stdout.as_str())),
        ("stderr", Some(evidence.stderr.as_str())),
        ("before", Some(evidence.native_observation.as_str())),
        ("retirement", Some(evidence.retirement.as_str())),
    ] {
        if actual != Some(path(role)?) {
            return Err("special normalized artifact replaces actual native capture".into());
        }
    }
    let expected = provider(product, resolve)?;
    let public = document(path("result")?, resolve)?;
    result(&public)?;
    let sidecar = document(path("terminal")?, resolve)?;
    header(&sidecar, "memcordon.windows-terminal-observation", 2)?;
    let terminal = &sidecar["terminal"];
    super::windows_proof::validate_windows_proof_matrix(terminal)?;
    validate_terminal_authority(
        terminal,
        sidecar["terminal_authority_json"]
            .as_str()
            .ok_or("special actual terminal authority absent")?,
        &sidecar["frontend_delivery"],
    )?;
    let (declared, request_sha) = request(&resolve(path("request")?)?)?;
    let launch_bytes = bytes_json(&sidecar["provider_request"])?;
    let launch = crate::validate_json_document(&launch_bytes)?;
    fields(
        &public["request"],
        &[
            "request_sha256",
            "invocation_sha256",
            "resource_policy_sha256",
            "runtime_sha256",
            "input_sha256",
        ],
        &[],
    )?;
    crate::digest(
        public["request"]["resource_policy_sha256"]
            .as_str()
            .ok_or("actual native resource association digest absent")?,
    )?;
    if public["request"]["resource_policy_sha256"] != special_resource_digest() {
        return Err("special requested resource commitment differs from exact original finite CLI invocation".into());
    }
    if public["provider"] != expected
        || sidecar["provider"] != expected
        || launch["expected_provider_binding"] != expected
        || launch["schema_version"] != 4
        || launch["workload_request"] != declared
        || crate::sha256(&launch_bytes) != terminal["request_sha256"]
        || launch["nonce"] != terminal["nonce"]
        || public["request"]["request_sha256"] != request_sha
        || !public["request"]["runtime_sha256"].is_null()
        || !public["request"]["input_sha256"].is_null()
        || public["release"] != "released"
        || public["cleanup"]["state"] != "complete"
        || terminal["schema_version"] != 3
        || terminal["payload"]["kind"] != "execution"
    {
        return Err("special current request/provider/terminal/release binding differs".into());
    }
    let native = &public["runtime"]["native"];
    fields(&public["runtime"], &["kind", "profile", "native"], &[])?;
    if public["runtime"]["kind"] != "windows-sealed"
        || public["runtime"]["profile"] != "windows-sealed-current-token-v1"
        || native["schema_version"] != 3
        || native["credential_transition_disposition"] != "preserve-caller-envelope"
    {
        return Err("special native Windows execution absent".into());
    }
    let obligations = public["cleanup"]["obligations"]
        .as_array()
        .ok_or("special native cleanup inventory absent")?;
    let mut resources = BTreeSet::new();
    for obligation in obligations {
        fields(obligation, &["resource", "settled"], &[])?;
        if obligation["settled"] != true
            || !resources.insert(
                obligation["resource"]
                    .as_str()
                    .ok_or("special cleanup resource absent")?,
            )
        {
            return Err("special cleanup obligation unsettled or duplicated".into());
        }
    }
    if resources != BTreeSet::from(["target", "aggregate", "job", "guardian", "relays", "record"]) {
        return Err("special cleanup obligation inventory differs".into());
    }
    yes(
        native,
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
    let association = json!({"provider":expected,"attempt_id":terminal["attempt_id"],"request_sha256":terminal["request_sha256"]});
    if public["windows_attempt"] != association
        || native["frontend_provider_association"] != association
        || native["retirement"] != terminal["retirement_proof"]
        || native["target_identity"] != terminal["process_observation"]["root_identity"]
        || native["process_observation"] != terminal["process_observation"]
        || native["frontend_delivery"]["terminal_sha256"]
            != sidecar["frontend_delivery"]["terminal_sha256"]
        || native["frontend_delivery"]["retired_sha256"]
            != sidecar["frontend_delivery"]["retired_sha256"]
    {
        return Err(
            "special public native facts differ from original acknowledged terminal".into(),
        );
    }
    yes(
        &native["frontend_delivery"],
        &["terminal_validated", "acknowledgement_observed"],
    )?;
    let invocation = document(path("invocation")?, resolve)?;
    let reported: Invocation =
        serde_json::from_value(public["invocation"].clone()).map_err(|error| error.to_string())?;
    if reported.syntax != "plus-budgets-v1"
        || reported.memory_token.as_deref() != Some("+4GiB")
        || reported.deadline_token.as_deref() != Some("+120s")
        || public["request"]["invocation_sha256"]
            != crate::sha256(&serde_json::to_vec(&reported).map_err(|error| error.to_string())?)
    {
        return Err("special actual invocation/request association differs".into());
    }
    let mut boundary = terminal["payload"]["boundary_detail"].clone();
    if boundary["mechanism"] != "windows-job-object-v3" {
        return Err("special actual current native mechanism absent".into());
    }
    boundary
        .as_object_mut()
        .ok_or("special native boundary object absent")?
        .remove("mechanism");
    let mut projected = native.clone();
    for field in [
        "frontend_delivery",
        "frontend_provider_association",
        "retirement",
    ] {
        projected
            .as_object_mut()
            .ok_or("special public native object absent")?
            .remove(field);
        boundary.as_object_mut().unwrap().remove(field);
    }
    if projected != boundary {
        return Err("special result changes actual native terminal facts".into());
    }
    let cli = product
        .components
        .iter()
        .find(|component| component.role == "public-cli")
        .ok_or("actual selected public CLI absent")?;
    if invocation["image_sha256"] != cli.installed_sha256
        || crate::sha256(&resolve(path("public_cli")?)?) != cli.installed_sha256
    {
        return Err("special invocation substitutes selected public CLI bytes".into());
    }
    header(
        &invocation,
        "memcordon.windows-installed-special-invocation",
        1,
    )?;
    let argv: Vec<Vec<u16>> = serde_json::from_value(invocation["argv_utf16"].clone())
        .map_err(|error| error.to_string())?;
    let sentinel = "--".encode_utf16().collect::<Vec<_>>();
    let positions = argv
        .iter()
        .enumerate()
        .filter(|(_, arg)| **arg == sentinel)
        .map(|(index, _)| index)
        .collect::<Vec<_>>();
    if positions.len() != 1
        || argv.get(0) != Some(&"+4GiB".encode_utf16().collect::<Vec<_>>())
        || argv.get(1) != Some(&"+120s".encode_utf16().collect::<Vec<_>>())
        || argv.get(2) != Some(&"--sealed".encode_utf16().collect::<Vec<_>>())
        || positions[0] + 3 != argv.len()
        || argv.last() != Some(&mode.encode_utf16().collect::<Vec<_>>())
        || launch["command"]["program"] != json!(argv[positions[0] + 1])
        || launch["command"]["arguments"] != json!([argv[positions[0] + 2].clone()])
        || invocation["mode"] != mode
        || launch["policy"]["memory_limit_bytes"] != 4u64 * 1024 * 1024 * 1024
        || launch["policy"]["lifetime"] != "command"
        || launch["policy"]["poll_interval_millis"] != 50
        || launch["policy"]["signal_grace_millis"] != 2000
        || launch["policy"]["command_exit_grace_millis"] != 0
        || launch["policy"]["limit_grace_millis"] != 0
        || launch["policy"]["absolute_deadline_millis"]
            .as_u64()
            .is_none_or(|value| value == 0)
    {
        return Err(
            "special native target command/resources differ from actual original CLI invocation"
                .into(),
        );
    }
    let before = document(path("before")?, resolve)?;
    header(&before, "memcordon.windows-installed-special-native", 1)?;
    let retired = document(path("retirement")?, resolve)?;
    header(
        &retired,
        "memcordon.windows-installed-special-retirement",
        1,
    )?;
    let exit = document(path("exit")?, resolve)?;
    header(&exit, "memcordon.windows-installed-special-exit", 1)?;
    if before["case"] != case
        || retired["case"] != case
        || exit["case"] != case
        || before["expected_provider"] != expected
        || retired["same_image_processes_absent"] != true
        || exit["timed_out"] != false
        || !exit["execution_error"].is_null()
        || exit["native_status"] != public["outcome"]["wrapper_status"]
    {
        return Err("special actual capture/wait/retirement incomplete".into());
    }
    let family = before["family"]
        .as_array()
        .ok_or("original special held family absent")?;
    let retired_family = retired["family"]
        .as_array()
        .ok_or("special original held family retirement absent")?;
    let expected_count = if population { 257 } else { 1 };
    if family.len() != expected_count || retired_family.len() != expected_count {
        return Err("actual original special native family count differs".into());
    }
    let mut held = BTreeSet::new();
    let mut closed = BTreeMap::new();
    for row in family {
        let identity = (
            row["pid"]
                .as_u64()
                .filter(|pid| *pid != 0)
                .ok_or("held native PID absent")?,
            row["birth"].as_u64().ok_or("held native birth absent")?,
        );
        if row["live"] != true || !held.insert(identity) {
            return Err("special family was not held uniquely live before action".into());
        }
    }
    for row in retired_family {
        let identity = (
            row["pid"].as_u64().ok_or("retired PID absent")?,
            row["birth"].as_u64().ok_or("retired birth absent")?,
        );
        let status = row["native_exit_status"]
            .as_u64()
            .filter(|status| u32::try_from(*status).is_ok())
            .ok_or("original held native exit status absent")?;
        if row["retired"] != true || closed.insert(identity, status).is_some() {
            return Err("special original family native retirement incomplete".into());
        }
    }
    if held != closed.keys().copied().collect() {
        return Err("special retirement replaced original live family".into());
    }
    let root = (
        native["target_identity"]["process_id"]
            .as_u64()
            .ok_or("actual root PID absent")?,
        native["target_identity"]["creation_time_100ns"]
            .as_u64()
            .ok_or("actual root birth absent")?,
    );
    let native_status = *closed
        .get(&root)
        .ok_or("terminal target differs from original held family")?;
    let run = &terminal["payload"]["outcome"];
    let direct = &run["child_after_termination"];
    if public["outcome"]["native_termination"] != *direct
        || !((direct["kind"] == "windows-status" && direct["status"] == native_status)
            || (direct["kind"] == "exit-code" && direct["code"] == native_status))
    {
        return Err("special direct target native wait differs from actual original handle".into());
    }
    let stdout = resolve(path("stdout")?)?;
    resolve(path("stderr")?)?;
    if population {
        if public["outcome"]["kind"] != "deadline"
            || run["outcome"] != "deadline-exceeded"
            || !public["provider_failure"].is_null()
        {
            return Err("257-process population lacks actual ordinary deadline termination".into());
        }
        validate_population_readiness(&stdout, &held, root)?;
    } else {
        if public["outcome"]["kind"] != "provider-failure" || run["outcome"] != "monitor-failed" {
            return Err(
                "actual guardian loss was relabelled as target success or resource limit".into(),
            );
        }
        let failure = &public["provider_failure"];
        super::windows_diagnostics::validate_projection(failure)?;
        let event = &failure["original"]["observed"]["event"];
        if failure["attempt_id"] != terminal["attempt_id"]
            || failure["request_sha256"] != terminal["request_sha256"]
            || event["category"] != "monitor"
            || event["operation"] != "check-guardian"
            || event["code"] != "guardian-loss"
            || !event["native_code"].is_null()
            || event["observed_phase"] != "monitoring"
        {
            return Err("guardian first cause replaced actual original monitoring failure".into());
        }
        let live = document(path("guardian_live")?, resolve)?;
        let readiness = stdout
            .split(|byte| *byte == b'\n')
            .filter_map(|line| line.strip_prefix(b"MEMCORDON-GUARDIAN-LOSS-READY:"))
            .collect::<Vec<_>>();
        if readiness.len() != 1 {
            return Err("guardian original readiness absent or duplicated".into());
        }
        let ready = crate::validate_json_document(readiness[0])?;
        if ready["schema_version"] != 1
            || ready["pid"].as_u64() != Some(root.0)
            || ready["birth"].as_u64() != Some(root.1)
        {
            return Err("guardian-loss readiness differs from original held target".into());
        }
        let action = document(path("guardian_action")?, resolve)?;
        header(&action, "memcordon.windows-installed-guardian-action", 1)?;
        let guardian = &action["guardian"];
        if live["association"] != association
            || live["guardian_identity"]["process_id"] != guardian["process_id"]
            || live["guardian_identity"]["creation_time_100ns"] != guardian["creation_time_100ns"]
            || live["live_target_identity"] != native["target_identity"]
            || action["api"] != "TerminateProcess"
            || action["exit_code_operand"] != 137
            || action["call_succeeded"] != true
            || action["native_exit_status"] != 137
            || action["held_process_retired"] != true
            || guardian["generation_manifest_sha256"] != expected["runtime_manifest_sha256"]
        {
            return Err("guardian action lacks exact original live provider/target/SCM process association and native wait137".into());
        }
        let query = document(path("guardian_query_capture")?, resolve)?;
        if query["operation_complete"] != true
            || query["observed_exit_code"] != 0
            || !query["failure"].is_null()
        {
            return Err("guardian original observation did not complete successfully".into());
        }
    }
    Ok(())
}

pub fn validate_population_readiness(
    stdout: &[u8],
    held: &BTreeSet<(u64, u64)>,
    root: (u64, u64),
) -> VerificationResult<()> {
    let mut observed = BTreeSet::new();
    let mut ordinals = BTreeSet::new();
    let mut roots = 0;
    for line in stdout.split(|byte| *byte == b'\n') {
        let Some(bytes) = line.strip_prefix(b"MEMCORDON-INVENTORY-READY:") else {
            continue;
        };
        let row = crate::validate_json_document(bytes)?;
        fields(&row, &["kind", "ordinal", "pid", "birth"], &[])?;
        let identity = (
            row["pid"]
                .as_u64()
                .filter(|pid| *pid != 0)
                .ok_or("population readiness PID absent")?,
            row["birth"]
                .as_u64()
                .ok_or("population readiness birth absent")?,
        );
        if !observed.insert(identity) {
            return Err("population readiness duplicate native identity".into());
        }
        match row["kind"].as_str() {
            Some("inventory-root-ready") if row["ordinal"].is_null() && identity == root => {
                roots += 1
            }
            Some("inventory-leaf-ready") => {
                let ordinal = row["ordinal"]
                    .as_u64()
                    .filter(|ordinal| *ordinal < 256)
                    .ok_or("population ordinal outside actual 256-leaf fixture")?;
                if !ordinals.insert(ordinal) {
                    return Err("population duplicate leaf ordinal".into());
                }
            }
            _ => return Err("unknown actual population readiness operation".into()),
        };
    }
    if roots != 1 || ordinals.len() != 256 || observed.len() != 257 || &observed != held {
        return Err("population readiness differs from all 257 original held processes".into());
    }
    Ok(())
}

pub fn prepared_commitment(prepared: &Value) -> VerificationResult<String> {
    header(prepared, "memcordon.windows-workload-prepared", 1)?;
    fields(
        prepared,
        &[
            "format",
            "revision",
            "attempt_id",
            "nonce",
            "request_sha256",
            "target",
            "owner_manifest_sha256",
        ],
        &[],
    )?;
    fields(
        &prepared["target"],
        &["process_id", "creation_time_100ns"],
        &[],
    )?;
    for name in ["attempt_id", "request_sha256", "owner_manifest_sha256"] {
        crate::digest(
            prepared[name]
                .as_str()
                .ok_or("prepared native digest absent")?,
        )?;
    }
    if prepared["nonce"].as_str().is_none_or(str::is_empty)
        || prepared["target"]["process_id"]
            .as_u64()
            .is_none_or(|pid| pid == 0 || pid > u64::from(u32::MAX))
        || prepared["target"]["creation_time_100ns"].as_u64().is_none()
    {
        return Err("prepared native target/nonce absent".into());
    }
    struct Ordered<'a>(&'a Value, bool);
    impl Serialize for Ordered<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeMap;
            let names: &[&str] = if self.1 {
                &["process_id", "creation_time_100ns"]
            } else {
                &[
                    "format",
                    "revision",
                    "attempt_id",
                    "nonce",
                    "request_sha256",
                    "target",
                    "owner_manifest_sha256",
                ]
            };
            let mut map = serializer.serialize_map(Some(names.len()))?;
            for name in names {
                if *name == "target" {
                    map.serialize_entry(name, &Ordered(&self.0[name], true))?;
                } else {
                    map.serialize_entry(name, &self.0[name])?;
                }
            }
            map.end()
        }
    }
    Ok(crate::sha256(
        &serde_json::to_vec(&Ordered(prepared, false)).map_err(|error| error.to_string())?,
    ))
}

pub fn validate_control_message(
    message: &Value,
    variant: &str,
    binding: &Value,
    commitment: Option<&str>,
) -> VerificationResult<()> {
    let hash_field = match variant {
        "cancel" => None,
        "preparation-acknowledged" => Some("accepted_sha256"),
        "prepared-acknowledged" => Some("prepared_sha256"),
        _ => return Err("unsupported current control message".into()),
    };
    let mut required = vec![
        "message",
        "schema_version",
        "attempt_id",
        "nonce",
        "request_sha256",
    ];
    required.push(hash_field.unwrap_or("signal"));
    fields(message, &required, &[])?;
    if message["message"] != variant || message["schema_version"] != 4 {
        return Err("current caller control discriminator/version mismatch".into());
    }
    for field in ["attempt_id", "nonce", "request_sha256"] {
        if message[field] != binding[field] {
            return Err("current caller control message crosses actual association".into());
        }
    }
    match hash_field {
        Some(field) => {
            if commitment.is_none() || message[field].as_str() != commitment {
                return Err("current caller acknowledgment changes original native carrier".into());
            }
        }
        None => {
            if commitment.is_some() || message["signal"] != 2 {
                return Err("current caller cancellation signal mismatch".into());
            }
        }
    }
    Ok(())
}

pub fn accepted_commitment(accepted: &Value) -> VerificationResult<String> {
    header(accepted, "memcordon.windows-workload-accepted", 1)?;
    fields(
        accepted,
        &[
            "format",
            "revision",
            "provider",
            "frontend",
            "attempt_id",
            "nonce",
            "request_sha256",
            "setup_deadline_millis",
        ],
        &[],
    )?;
    fields(
        &accepted["provider"],
        &["generation", "source_commit", "runtime_manifest_sha256"],
        &[],
    )?;
    fields(
        &accepted["frontend"],
        &["process_id", "creation_time_100ns"],
        &[],
    )?;
    for field in ["attempt_id", "request_sha256"] {
        crate::digest(
            accepted[field]
                .as_str()
                .ok_or("native accepted digest absent")?,
        )?;
    }
    crate::digest(
        accepted["provider"]["runtime_manifest_sha256"]
            .as_str()
            .ok_or("accepted provider manifest digest absent")?,
    )?;
    let generation = accepted["provider"]["generation"]
        .as_str()
        .ok_or("accepted provider generation absent")?;
    let commit = accepted["provider"]["source_commit"]
        .as_str()
        .ok_or("accepted provider source absent")?;
    if generation.is_empty()
        || generation.len() > 256
        || !generation
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
        || ![
            std::mem::size_of::<[u8; 20]>() * 2,
            std::mem::size_of::<[u8; 32]>() * 2,
        ]
        .contains(&commit.len())
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("accepted actual provider identity malformed".into());
    }
    if accepted["nonce"]
        .as_str()
        .is_none_or(|nonce| nonce.is_empty() || nonce.len() > 128)
        || accepted["provider"]["generation"]
            .as_str()
            .is_none_or(str::is_empty)
        || accepted["frontend"]["process_id"]
            .as_u64()
            .is_none_or(|pid| pid == 0 || pid > u64::from(u32::MAX))
        || accepted["frontend"]["creation_time_100ns"]
            .as_u64()
            .is_none()
        || accepted["setup_deadline_millis"]
            .as_u64()
            .is_none_or(|cutoff| cutoff == 0)
    {
        return Err("invalid accepted native caller/cutoff binding".into());
    }
    struct Ordered<'a>(&'a Value, u8);
    impl Serialize for Ordered<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            use serde::ser::SerializeMap;
            let fields: &[&str] = match self.1 {
                1 => &["generation", "source_commit", "runtime_manifest_sha256"],
                2 => &["process_id", "creation_time_100ns"],
                _ => &[
                    "format",
                    "revision",
                    "provider",
                    "frontend",
                    "attempt_id",
                    "nonce",
                    "request_sha256",
                    "setup_deadline_millis",
                ],
            };
            let mut map = serializer.serialize_map(Some(fields.len()))?;
            for field in fields {
                match *field {
                    "provider" => map.serialize_entry(field, &Ordered(&self.0[field], 1))?,
                    "frontend" => map.serialize_entry(field, &Ordered(&self.0[field], 2))?,
                    _ => map.serialize_entry(field, &self.0[field])?,
                }
            }
            map.end()
        }
    }
    Ok(crate::sha256(
        &serde_json::to_vec(&Ordered(accepted, 0)).map_err(|error| error.to_string())?,
    ))
}

fn validate_public_windows_association(
    public: &Value,
    terminal: &Value,
    provider: &Value,
) -> VerificationResult<()> {
    let association = json!({"provider":provider,"attempt_id":terminal["attempt_id"],"request_sha256":terminal["request_sha256"]});
    if public["windows_attempt"] != association
        || public["runtime"]["native"]["frontend_provider_association"] != association
    {
        return Err("current result changes actual native attempt/provider association".into());
    }
    Ok(())
}

fn current_service_restart(
    evidence: &CaseEvidenceV2,
    input: &Value,
    product: &ProductObservationV2,
    resolve: Resolver<'_>,
) -> VerificationResult<()> {
    header(input, "memcordon.windows-current-service-restart-case", 1)?;
    fields(
        input,
        &[
            "format",
            "revision",
            "key",
            "run_id",
            "source_commit",
            "source_tree_sha256",
            "lease_id",
            "artifacts",
            "target_fixture",
            "target_fixture_sha256",
            "owner",
        ],
        &[],
    )?;
    if input["key"] != serde_json::to_value(&evidence.key).map_err(|error| error.to_string())?
        || input["run_id"] != evidence.run_id
        || input["source_commit"] != product.source_commit
        || input["source_tree_sha256"] != product.source_tree_sha256
        || input["lease_id"] != product.lifecycle.lease_id
        || evidence.lease_id.as_deref() != Some(product.lifecycle.lease_id.as_str())
        || evidence.retirement != product.lifecycle.receipt
        || evidence.attempt_observation.is_some()
        || evidence.recovery.is_some()
        || evidence.component_recipe_id.is_some()
    {
        return Err("current service restart source/lease or factual roles differ".into());
    }
    fields(
        &input["artifacts"],
        &[
            "invocation.json",
            "request.json",
            "service.json",
            "result.json",
            "terminal.json",
            "wait.json",
            "stdout.bin",
            "stderr.bin",
        ],
        &[],
    )?;
    let path = |role: &str| {
        input["artifacts"][role]
            .as_str()
            .ok_or_else(|| format!("original service restart {role} absent"))
    };
    for (role, actual) in [
        ("invocation.json", Some(evidence.invocation.as_str())),
        ("request.json", evidence.request.as_deref()),
        ("result.json", evidence.raw_result.as_deref()),
        ("terminal.json", evidence.authenticated_terminal.as_deref()),
        ("service.json", Some(evidence.native_observation.as_str())),
        ("stdout.bin", Some(evidence.stdout.as_str())),
        ("stderr.bin", Some(evidence.stderr.as_str())),
    ] {
        if actual != Some(path(role)?) {
            return Err("current service restart substitutes artifact role".into());
        }
    }
    let owner = document(
        input["owner"]
            .as_str()
            .ok_or("original restart owner absent")?,
        resolve,
    )?;
    header(
        &owner,
        "memcordon.consumer-readiness.windows-lease-owner",
        2,
    )?;
    if owner["identity"]["run_id"] != evidence.run_id
        || owner["identity"]["source_commit"] != product.source_commit
        || owner["identity"]["source_tree_sha256"] != product.source_tree_sha256
        || owner["key"] != serde_json::to_value(&product.key).map_err(|error| error.to_string())?
    {
        return Err("service restart replaces original protected source owner".into());
    }
    let current = &owner["current"];
    let provider = provider(product, resolve)?;
    let component = |role: &str| {
        product
            .components
            .iter()
            .find(|component| component.role == role)
            .ok_or("selected measured restart component absent")
    };
    let cli = component("public-cli")?;
    let agent = component("sealed-agent")?;
    if current["source_commit"] != product.source_commit
        || current["target"] != product.key.target
        || current["version"] != product.version
        || current["cli"]["sha256"] != cli.installed_sha256
        || current["agent"]["sha256"] != agent.installed_sha256
        || evidence.fixture_sha256 != cli.installed_sha256
        || crate::sha256(&resolve(&evidence.fixture)?) != cli.installed_sha256
    {
        return Err("service restart changes selected current product bytes".into());
    }
    let target_fixture = input["target_fixture"]
        .as_str()
        .ok_or("fresh request fixture absent")?;
    if !evidence.outputs.contains(&target_fixture.to_owned())
        || crate::sha256(&resolve(target_fixture)?) != input["target_fixture_sha256"]
        || input["target_fixture_sha256"] != current["fixture"]["sha256"]
    {
        return Err("service restart changes actual fixture bytes".into());
    }
    let service = document(path("service.json")?, resolve)?;
    header(&service, "memcordon.windows-current-service-restart", 1)?;
    fields(
        &service,
        &[
            "format",
            "revision",
            "service_name",
            "api",
            "before",
            "after",
            "original",
            "replacement",
            "original_wait",
            "replacement_wait",
            "image_utf16",
            "image_sha256",
            "prior_result_bytes",
            "prior_terminal_bytes",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
        &[],
    )?;
    for field in ["before", "after"] {
        fields(&service[field], &["process_id", "current_state"], &[])?;
        if service[field]["current_state"] != 4
            || service[field]["process_id"]
                .as_u64()
                .is_none_or(|pid| pid == 0 || pid > u64::from(u32::MAX))
        {
            return Err("actual SCM current process identity/state absent".into());
        }
    }
    for (identity, status) in [("original", "before"), ("replacement", "after")] {
        fields(
            &service[identity],
            &["process_id", "creation_time_100ns"],
            &[],
        )?;
        if service[identity]["process_id"] != service[status]["process_id"]
            || service[identity]["creation_time_100ns"].as_u64().is_none()
        {
            return Err("SCM process does not match original held native handle".into());
        }
    }
    let encode = |text: &str| text.encode_utf16().collect::<Vec<_>>();
    if service["service_name"] != "MemCordonSealedControl"
        || service["api"]
            != "OpenSCManagerW/OpenServiceW/QueryServiceStatusEx/ControlService/StartServiceW"
        || service["original"] == service["replacement"]
        || service["original_wait"] != 0
        || service["replacement_wait"] != 258
        || service["image_sha256"] != agent.installed_sha256
        || service["image_utf16"]
            != json!(encode(
                current["installed_agent"]["path"]
                    .as_str()
                    .ok_or("actual installed control image absent")?
            ))
        || service["work_deadline_unix_millis"] != owner["work_deadline_unix_millis"]
        || service["cleanup_deadline_unix_millis"] != owner["cleanup_deadline_unix_millis"]
    {
        return Err("service restart lacks actual old process retirement/new selected owner or original cutoff".into());
    }
    let prior = crate::validate_json_document(&bytes_json(&service["prior_result_bytes"])?)?;
    result(&prior)?;
    let prior_sidecar =
        crate::validate_json_document(&bytes_json(&service["prior_terminal_bytes"])?)?;
    header(&prior_sidecar, "memcordon.windows-terminal-observation", 2)?;
    super::windows_proof::validate_windows_proof_matrix(&prior_sidecar["terminal"])?;
    validate_terminal_authority(
        &prior_sidecar["terminal"],
        prior_sidecar["terminal_authority_json"]
            .as_str()
            .ok_or("prior cancellation native authority absent")?,
        &prior_sidecar["frontend_delivery"],
    )?;
    if prior["provider"] != provider
        || prior_sidecar["provider"] != provider
        || prior["release"] != "released"
        || prior["outcome"]["kind"] != "interrupted"
        || prior["outcome"]["wrapper_status"] != 130
        || prior["cleanup"]["state"] != "complete"
        || prior["runtime"]["native"]["retirement"] != prior_sidecar["terminal"]["retirement_proof"]
        || prior["runtime"]["native"]["frontend_delivery"] != prior_sidecar["frontend_delivery"]
    {
        return Err("restart does not follow actual settled current cancellation".into());
    }
    let public = document(path("result.json")?, resolve)?;
    result(&public)?;
    let sidecar = document(path("terminal.json")?, resolve)?;
    header(&sidecar, "memcordon.windows-terminal-observation", 2)?;
    let terminal = &sidecar["terminal"];
    super::windows_proof::validate_windows_proof_matrix(terminal)?;
    validate_terminal_authority(
        terminal,
        sidecar["terminal_authority_json"]
            .as_str()
            .ok_or("fresh current native authority absent")?,
        &sidecar["frontend_delivery"],
    )?;
    let raw = bytes_json(&sidecar["provider_request"])?;
    let launch = crate::validate_json_document(&raw)?;
    super::windows_actors::validate_launch_request(&launch)?;
    let (declared, declared_hash) = request(&resolve(path("request.json")?)?)?;
    if public["provider"] != provider
        || sidecar["provider"] != provider
        || launch["expected_provider_binding"] != provider
        || launch["workload_request"] != declared
        || public["request"]["request_sha256"] != declared_hash
        || terminal["request_sha256"] != crate::sha256(&raw)
        || launch["nonce"] != terminal["nonce"]
        || public["windows_attempt"]["attempt_id"] != terminal["attempt_id"]
        || public["windows_attempt"]["request_sha256"] != terminal["request_sha256"]
        || public["windows_attempt"]["provider"] != provider
        || terminal["attempt_id"] == prior_sidecar["terminal"]["attempt_id"]
        || terminal["nonce"] == prior_sidecar["terminal"]["nonce"]
    {
        return Err(
            "restart fresh request reused prior attempt authority or changed native source binding"
                .into(),
        );
    }
    validate_public_windows_association(&public, terminal, &provider)?;
    validate_public_windows_association(&prior, &prior_sidecar["terminal"], &provider)?;
    let boundary = &terminal["payload"]["boundary_detail"];
    validate_prepared_boundary(boundary)?;
    yes(
        boundary,
        &[
            "target_released",
            "target_created_suspended",
            "active_processes_zero",
            "direct_target_reaped",
            "relays_retired",
            "guardian_reaped",
            "final_job_handles_closed",
        ],
    )?;
    let mut actual = boundary.clone();
    actual
        .as_object_mut()
        .ok_or("fresh native boundary absent")?
        .remove("mechanism");
    let mut projected = public["runtime"]["native"].clone();
    for field in [
        "frontend_delivery",
        "frontend_provider_association",
        "retirement",
    ] {
        actual.as_object_mut().unwrap().remove(field);
        projected
            .as_object_mut()
            .ok_or("fresh current native result absent")?
            .remove(field);
    }
    fields(&public["runtime"], &["kind", "profile", "native"], &[])?;
    if public["runtime"]["kind"] != "windows-sealed"
        || public["runtime"]["profile"] != "windows-sealed-current-token-v1"
        || actual != projected
        || public["runtime"]["native"]["retirement"] != terminal["retirement_proof"]
        || public["runtime"]["native"]["frontend_delivery"] != sidecar["frontend_delivery"]
        || public["release"] != "released"
        || public["outcome"]["kind"] != "completed"
        || public["outcome"]["wrapper_status"] != 0
        || public["cleanup"]["state"] != "complete"
        || terminal["payload"]["kind"] != "execution"
        || terminal["payload"]["outcome"]["outcome"] != "exited"
        || public["outcome"]["native_termination"] != terminal["payload"]["outcome"]["child"]
        || ![
            json!({"kind":"exit-code","code":0}),
            json!({"kind":"windows-status","status":0}),
        ]
        .contains(&public["outcome"]["native_termination"])
    {
        return Err("fresh request lacks actual executed target wait/native retirement/ACK".into());
    }
    let directory = format!(
        "{}\\current-controls\\service-restart-fresh-request",
        current["output_directory"]
            .as_str()
            .ok_or("original output root absent")?
            .trim_end_matches(['\\', '/'])
    );
    let fixture = current["fixture"]["path"]
        .as_str()
        .ok_or("actual selected fixture path absent")?;
    let args = vec![
        encode(fixture),
        encode("exit"),
        encode("--code"),
        encode("0"),
    ];
    let invocation = document(path("invocation.json")?, resolve)?;
    header(
        &invocation,
        "memcordon.windows-current-control-invocation",
        1,
    )?;
    let expected_args = vec![
        encode("--boundary"),
        encode("sealed"),
        encode("--workload-request"),
        encode(&format!("{directory}\\request.json")),
        encode("--report-format"),
        encode("result-v3"),
        encode("--report"),
        encode(&format!("{directory}\\result.json")),
        encode("--windows-terminal-observation"),
        encode(&format!("{directory}\\terminal.json")),
        encode("--"),
        encode(fixture),
        encode("exit"),
        encode("--code"),
        encode("0"),
    ];
    if invocation["scenario"] != "service-restart-fresh-request"
        || invocation["program_utf16"]
            != json!(encode(
                current["cli"]["path"]
                    .as_str()
                    .ok_or("actual CLI path absent")?
            ))
        || invocation["argv_utf16"] != json!(expected_args)
        || invocation["cwd_utf16"] != json!(encode(&directory))
        || invocation["environment_cleared"] != true
        || invocation["frontend_environment"] != launch["environment"]
        || invocation["work_deadline_unix_millis"] != owner["work_deadline_unix_millis"]
        || invocation["cleanup_deadline_unix_millis"] != owner["cleanup_deadline_unix_millis"]
        || launch["command"]["program"] != json!(args[0])
        || launch["command"]["arguments"] != json!(args[1..])
        || public["request"]["invocation_sha256"]
            != crate::wire::invocation_digest_parts(
                &crate::NativeArguments::WindowsUtf16(args),
                &[],
                &None,
                &None,
            )?
        || public["request"]["resource_policy_sha256"] != resources::default_resource_digest()
    {
        return Err(
            "fresh current request changed actual source invocation/environment/original deadline"
                .into(),
        );
    }
    let wait = document(path("wait.json")?, resolve)?;
    header(&wait, "memcordon.windows-current-control-wait", 1)?;
    let stdout = resolve(&evidence.stdout)?;
    let stderr = resolve(&evidence.stderr)?;
    if wait["native_status"] != 0
        || !stdout.is_empty()
        || wait["stdout_sha256"] != crate::sha256(&stdout)
        || wait["stderr_sha256"] != crate::sha256(&stderr)
    {
        return Err("fresh current frontend native wait/streams differ".into());
    }
    Ok(())
}

fn current_preallocation_cancel(
    evidence: &CaseEvidenceV2,
    input: &Value,
    product: &ProductObservationV2,
    resolve: Resolver<'_>,
) -> VerificationResult<()> {
    header(input, "memcordon.windows-current-preallocation-case", 1)?;
    fields(
        input,
        &[
            "format",
            "revision",
            "key",
            "run_id",
            "source_commit",
            "source_tree_sha256",
            "lease_id",
            "owner",
            "artifacts",
            "target_fixture",
            "target_fixture_sha256",
        ],
        &[],
    )?;
    if input["key"] != serde_json::to_value(&evidence.key).map_err(|error| error.to_string())?
        || input["run_id"] != evidence.run_id
        || input["source_commit"] != product.source_commit
        || input["source_tree_sha256"] != product.source_tree_sha256
        || input["lease_id"] != product.lifecycle.lease_id
        || evidence.lease_id.as_deref() != Some(product.lifecycle.lease_id.as_str())
        || evidence.retirement != product.lifecycle.receipt
        || evidence.authenticated_terminal.is_some()
        || evidence.recovery.is_some()
        || evidence.component_recipe_id.is_some()
    {
        return Err("preallocation source/lease changed or fabricated a target terminal".into());
    }
    fields(
        &input["artifacts"],
        &[
            "invocation.json",
            "request.json",
            "accepted.json",
            "native-launch.json",
            "cancel.json",
            "native-cancellation.json",
            "native.json",
            "result.json",
            "wait.json",
            "stdout.bin",
            "stderr.bin",
        ],
        &[],
    )?;
    let path = |role: &str| {
        input["artifacts"][role]
            .as_str()
            .ok_or_else(|| format!("actual preallocation {role} missing"))
    };
    for (role, actual) in [
        ("invocation.json", Some(evidence.invocation.as_str())),
        ("request.json", evidence.request.as_deref()),
        ("result.json", evidence.raw_result.as_deref()),
        ("accepted.json", evidence.attempt_observation.as_deref()),
        ("native.json", Some(evidence.native_observation.as_str())),
        ("stdout.bin", Some(evidence.stdout.as_str())),
        ("stderr.bin", Some(evidence.stderr.as_str())),
    ] {
        if actual != Some(path(role)?) {
            return Err("preallocation normalized artifact replaced original role".into());
        }
    }
    let owner = document(
        input["owner"]
            .as_str()
            .ok_or("preallocation original owner missing")?,
        resolve,
    )?;
    header(
        &owner,
        "memcordon.consumer-readiness.windows-lease-owner",
        2,
    )?;
    if owner["identity"]["run_id"] != evidence.run_id
        || owner["identity"]["source_commit"] != product.source_commit
        || owner["identity"]["source_tree_sha256"] != product.source_tree_sha256
        || owner["key"] != serde_json::to_value(&product.key).map_err(|error| error.to_string())?
    {
        return Err("preallocation actual owner source/cell differs".into());
    }
    let current = &owner["current"];
    let cli = product
        .components
        .iter()
        .find(|component| component.role == "public-cli")
        .ok_or("actual selected public CLI missing")?;
    if current["cli"]["sha256"] != cli.installed_sha256
        || evidence.fixture_sha256 != cli.installed_sha256
        || crate::sha256(&resolve(&evidence.fixture)?) != cli.installed_sha256
        || current["source_commit"] != product.source_commit
        || current["version"] != product.version
        || current["target"] != product.key.target
    {
        return Err("preallocation substitutes actual selected executable/source".into());
    }
    let target_fixture = input["target_fixture"]
        .as_str()
        .ok_or("declared never-dispatched fixture missing")?;
    if crate::sha256(&resolve(target_fixture)?) != input["target_fixture_sha256"]
        || input["target_fixture_sha256"] != current["fixture"]["sha256"]
    {
        return Err("preallocation declared target bytes substituted".into());
    }
    let accepted = document(path("accepted.json")?, resolve)?;
    let accepted_hash = accepted_commitment(&accepted)?;
    let expected_provider = provider(product, resolve)?;
    if accepted["provider"] != expected_provider {
        return Err(
            "preallocation accepted provider differs from actual selected native components".into(),
        );
    }
    let native_bytes = resolve(path("native-launch.json")?)?;
    let launch = crate::validate_json_document(&native_bytes)?;
    super::windows_actors::validate_launch_request(&launch)?;
    let (declared, declared_hash) = request(&resolve(path("request.json")?)?)?;
    if launch["expected_provider_binding"] != expected_provider
        || launch["workload_request"] != declared
        || launch["nonce"] != accepted["nonce"]
        || crate::sha256(&native_bytes) != accepted["request_sha256"]
    {
        return Err(
            "preallocation native/request binding differs from original caller bytes".into(),
        );
    }
    let cancel = document(path("cancel.json")?, resolve)?;
    validate_control_message(&cancel, "cancel", &accepted, None)?;
    fields(
        &cancel,
        &[
            "message",
            "schema_version",
            "attempt_id",
            "nonce",
            "request_sha256",
            "signal",
        ],
        &[],
    )?;
    if cancel["message"] != "cancel" || cancel["schema_version"] != 4 || cancel["signal"] != 2 {
        return Err("actual before-allocation cancellation request absent".into());
    }
    for field in ["attempt_id", "nonce", "request_sha256"] {
        if cancel[field] != accepted[field] {
            return Err("preallocation cancellation crosses actual native association".into());
        }
    }
    let raw_cancel = resolve(path("native-cancellation.json")?)?;
    let mut cancellation = crate::validate_json_document(&raw_cancel)?;
    fields(
        &cancellation,
        &[
            "kind",
            "format",
            "revision",
            "accepted",
            "signal",
            "primary_token_closed",
            "frontend_process_handle_closed",
        ],
        &[],
    )?;
    header(
        &cancellation,
        "memcordon.windows-preallocation-cancellation",
        1,
    )?;
    if cancellation["kind"] != "preallocation-cancelled"
        || cancellation["accepted"] != accepted
        || cancellation["signal"] != 2
    {
        return Err("actual native preallocation cancellation reply differs".into());
    }
    yes(
        &cancellation,
        &["primary_token_closed", "frontend_process_handle_closed"],
    )?;
    let native = document(path("native.json")?, resolve)?;
    header(&native, "memcordon.windows-current-preallocation-native", 1)?;
    if native["frontend"] != accepted["frontend"]
        || native["accepted_sha256"] != accepted_hash
        || native["cancel_sha256"] != crate::sha256(&resolve(path("cancel.json")?)?)
        || native["cancellation_sha256"] != crate::sha256(&raw_cancel)
    {
        return Err("preallocation original frontend/actual byte custody differs".into());
    }
    let pid = accepted["frontend"]["process_id"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .ok_or("native frontend PID missing")?;
    let birth = accepted["frontend"]["creation_time_100ns"]
        .as_u64()
        .ok_or("native frontend birth missing")?;
    let mut identity = sha2::Sha256::new();
    identity.update(
        accepted["nonce"]
            .as_str()
            .ok_or("native nonce missing")?
            .as_bytes(),
    );
    identity.update(pid.to_le_bytes());
    identity.update(birth.to_le_bytes());
    identity.update(crate::sha256(&native_bytes).as_bytes());
    if hex::encode(identity.finalize()) != accepted["attempt_id"] {
        return Err("preallocation native association does not name original held frontend".into());
    }
    let public = document(path("result.json")?, resolve)?;
    result(&public)?;
    cancellation.as_object_mut().unwrap().remove("kind");
    fields(
        &public["runtime"],
        &["kind", "profile", "cancellation"],
        &[],
    )?;
    if public["provider"] != expected_provider
        || public["release"] != "not-released"
        || public["runtime"]["kind"] != "windows-preallocation-cancelled"
        || public["runtime"]["profile"] != "windows-sealed-current-token-v1"
        || public["runtime"]["cancellation"] != cancellation
        || public["cleanup"] != json!({"state":"complete","obligations":[]})
        || public["outcome"]
            != json!({"kind":"interrupted","native_termination":null,"wrapper_status":130})
        || !public["provider_failure"].is_null()
        || !public["windows_rejection"].is_null()
    {
        return Err("preallocation result invented target/execution/cleanup authority".into());
    }
    let association = json!({"provider":expected_provider,"attempt_id":accepted["attempt_id"],"request_sha256":accepted["request_sha256"]});
    if public["windows_attempt"] != association
        || public["request"]["request_sha256"] != declared_hash
    {
        return Err("preallocation result/request association differs".into());
    }
    let invocation = document(path("invocation.json")?, resolve)?;
    header(
        &invocation,
        "memcordon.windows-current-control-invocation",
        1,
    )?;
    let encode = |value: &str| value.encode_utf16().collect::<Vec<_>>();
    let directory = format!(
        "{}\\current-controls\\before-preparation",
        current["output_directory"]
            .as_str()
            .ok_or("original preallocation output root missing")?
            .trim_end_matches(['\\', '/'])
    );
    let fixture_path = current["fixture"]["path"]
        .as_str()
        .ok_or("declared fixture path missing")?;
    let expected_args = vec![
        encode("--boundary"),
        encode("sealed"),
        encode("--workload-request"),
        encode(&format!("{directory}\\request.json")),
        encode("--workload-observation-directory"),
        encode(&format!("{directory}\\observations")),
        encode("--report-format"),
        encode("result-v3"),
        encode("--report"),
        encode(&format!("{directory}\\result.json")),
        encode("--"),
        encode(fixture_path),
        encode("exit"),
        encode("--code"),
        encode("0"),
    ];
    if invocation["scenario"] != "before-preparation"
        || invocation["program_utf16"]
            != json!(encode(
                current["cli"]["path"]
                    .as_str()
                    .ok_or("original frontend path missing")?
            ))
        || invocation["cwd_utf16"] != json!(encode(&directory))
        || invocation["argv_utf16"] != json!(expected_args)
        || invocation["work_deadline_unix_millis"] != owner["work_deadline_unix_millis"]
        || invocation["cleanup_deadline_unix_millis"] != owner["cleanup_deadline_unix_millis"]
        || invocation["environment_cleared"] != true
        || invocation["frontend_environment"] != launch["environment"]
    {
        return Err("preallocation actual command/environment/deadlines differ".into());
    }
    let args = vec![
        encode(fixture_path),
        encode("exit"),
        encode("--code"),
        encode("0"),
    ];
    if launch["command"]["program"] != json!(args[0])
        || launch["command"]["arguments"] != json!(args[1..])
        || public["request"]["invocation_sha256"]
            != crate::wire::invocation_digest_parts(
                &crate::NativeArguments::WindowsUtf16(args),
                &[],
                &None,
                &None,
            )?
        || public["request"]["resource_policy_sha256"] != resources::default_resource_digest()
    {
        return Err("preallocation actual native arguments/resource commitment differ".into());
    }
    let wait = document(path("wait.json")?, resolve)?;
    header(&wait, "memcordon.windows-current-control-wait", 1)?;
    let stdout = resolve(&evidence.stdout)?;
    let stderr = resolve(&evidence.stderr)?;
    if wait["native_status"] != 130
        || !stdout.is_empty()
        || wait["stdout_sha256"] != crate::sha256(&stdout)
        || wait["stderr_sha256"] != crate::sha256(&stderr)
    {
        return Err("actual preallocation frontend wait/streams differ".into());
    }
    Ok(())
}

pub fn validate_prepared_boundary(native: &Value) -> VerificationResult<()> {
    fields(
        native,
        &[
            "schema_version",
            "target_identity",
            "process_observation",
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
        ],
        &[
            "mechanism",
            "loader_qualification",
            "frontend_delivery",
            "frontend_provider_association",
            "retirement",
        ],
    )?;
    if native
        .get("mechanism")
        .is_some_and(|value| value != "windows-job-object-v3")
    {
        return Err("prepared boundary mechanism differs from current Windows native facts".into());
    }
    if native["schema_version"] != 3
        || native["service_identity"] != "MemCordonSealedControl+MemCordonSealedLauncher:v1"
        || native["credential_transition_disposition"] != "preserve-caller-envelope"
    {
        return Err("prepared native provider or credential transition differs".into());
    }
    yes(
        native,
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
        ],
    )
}

fn validate_drain_case(
    artifacts: &Value,
    owner: &Value,
    prepared: &Value,
    native: &Value,
    cancel: &Value,
    directory: &str,
    evidence: &CaseEvidenceV2,
    resolve: Resolver<'_>,
) -> VerificationResult<()> {
    let mut required = [
        "drain.json",
        "drain-recovery.json",
        "cancel-sent.json",
        "package-upgrade.invocation.json",
        "package-upgrade.capture.json",
        "package-upgrade.stdout.bin",
        "package-upgrade.stderr.bin",
    ]
    .map(str::to_owned)
    .to_vec();
    for operation in ["upgrade", "verify"] {
        for leaf in [
            "invocation.json",
            "capture.json",
            "stdout.bin",
            "stderr.bin",
        ] {
            required.push(format!("recovery/package-{operation}.{leaf}"));
        }
    }
    let names = required.iter().map(String::as_str).collect::<Vec<_>>();
    fields(artifacts, &names, &[])?;
    let path = |field: &str| {
        artifacts[field]
            .as_str()
            .ok_or_else(|| format!("actual drain {field} artifact absent"))
    };
    for value in artifacts.as_object().unwrap().values() {
        let path = value.as_str().ok_or("actual drain path not text")?;
        if !evidence.outputs.contains(&path.to_owned()) {
            return Err("actual drain capture not retained in its original source".into());
        }
        resolve(path)?;
    }
    let drain = document(path("drain.json")?, resolve)?;
    header(&drain, "memcordon.windows-current-package-drain", 1)?;
    fields(
        &drain,
        &[
            "format",
            "revision",
            "worker",
            "worker_image_utf16",
            "worker_wait",
            "mutex_name",
            "mutex_wait_before",
            "mutex_wait_after",
            "target",
            "target_wait_at_cancel",
            "cancel_sha256",
            "sent_sha256",
        ],
        &[],
    )?;
    fields(
        &drain["worker"],
        &["process_id", "creation_time_100ns"],
        &[],
    )?;
    let current = &owner["current"];
    let encode = |value: &str| value.encode_utf16().collect::<Vec<_>>();
    if drain["worker"]["process_id"]
        .as_u64()
        .is_none_or(|pid| pid == 0 || pid > u64::from(u32::MAX))
        || drain["worker"]["creation_time_100ns"].as_u64().is_none()
        || drain["worker"] == native["frontend"]
        || drain["worker_wait"] != 258
        || drain["worker_image_utf16"]
            != json!(encode(
                current["agent"]["path"]
                    .as_str()
                    .ok_or("selected drain native agent absent")?
            ))
        || drain["mutex_name"] != "Global\\MemCordonSealedPackageV1"
        || drain["mutex_wait_before"] != 258
        || drain["mutex_wait_after"] != 258
        || drain["target"] != prepared["target"]
        || drain["target_wait_at_cancel"] != native["target_wait_before_cancel"]
    {
        return Err("cancellation did not cross actual current package ownership with original native identities".into());
    }
    let sent = resolve(path("cancel-sent.json")?)?;
    let sent_message = crate::validate_json_document(&sent)?;
    validate_control_message(&sent_message, "cancel", prepared, None)?;
    if sent_message != *cancel
        || drain["sent_sha256"] != crate::sha256(&sent)
        || drain["cancel_sha256"] != crate::sha256(&sent)
        || native["cancel_sha256"] != crate::sha256(&sent)
    {
        return Err(
            "drain controller file was not the actual successful caller-channel cancellation write"
                .into(),
        );
    }
    let agent_path = current["agent"]["path"]
        .as_str()
        .ok_or("selected package agent path absent")?;
    let agent_hash = current["agent"]["sha256"]
        .as_str()
        .ok_or("selected package agent hash absent")?;
    let invocation = document(path("package-upgrade.invocation.json")?, resolve)?;
    let capture = document(path("package-upgrade.capture.json")?, resolve)?;
    validate_package_command_status(
        &invocation,
        &capture,
        "upgrade",
        agent_path,
        directory,
        agent_hash,
        125,
    )?;
    if !String::from_utf8_lossy(&resolve(path("package-upgrade.stderr.bin")?)?)
        .contains("MCSEALED-WINDOWS-UPGRADE-ROLLBACK-FAILED")
    {
        return Err("package drain did not reach actual native sharing interruption".into());
    }
    let recovery_directory = format!("{directory}\\package-recovery");
    for operation in ["upgrade", "verify"] {
        let invocation = document(
            path(&format!("recovery/package-{operation}.invocation.json"))?,
            resolve,
        )?;
        let capture = document(
            path(&format!("recovery/package-{operation}.capture.json"))?,
            resolve,
        )?;
        validate_package_command(
            &invocation,
            &capture,
            operation,
            agent_path,
            &recovery_directory,
            agent_hash,
        )?;
    }
    let recovery = document(path("drain-recovery.json")?, resolve)?;
    header(&recovery, "memcordon.windows-current-drain-recovery", 1)?;
    fields(
        &recovery,
        &[
            "format",
            "revision",
            "readback",
            "journal_path",
            "journal_absent",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
        &[],
    )?;
    let root = owner["binary_root"]
        .as_str()
        .ok_or("original current package root absent")?;
    if recovery["journal_path"].as_str().is_none_or(|path| {
        path.replace('/', "\\")
            != format!(
                "{}\\current-package-state.rollback.json",
                root.trim_end_matches(['\\', '/'])
            )
            .replace('/', "\\")
    }) || recovery["journal_absent"] != true
        || recovery["work_deadline_unix_millis"] != owner["work_deadline_unix_millis"]
        || recovery["cleanup_deadline_unix_millis"] != owner["cleanup_deadline_unix_millis"]
    {
        return Err("current drain recovery lost original ownership or extended its cutoff".into());
    }
    let mut expected = BTreeMap::new();
    for field in ["installed_agent", "installed_manifest"] {
        expected.insert(
            current[field]["path"]
                .as_str()
                .ok_or("current selected path absent")?
                .to_owned(),
            current[field]["sha256"].clone(),
        );
    }
    for selected in current["installed_components"]
        .as_array()
        .ok_or("current selected native components absent")?
    {
        expected.insert(
            selected["path"]
                .as_str()
                .ok_or("current selected component path absent")?
                .to_owned(),
            selected["sha256"].clone(),
        );
    }
    if recovery["readback"] != serde_json::to_value(expected).map_err(|error| error.to_string())? {
        return Err(
            "current package did not recover every actual installed artifact after drain".into(),
        );
    }
    Ok(())
}

fn current_held_cancel(
    evidence: &CaseEvidenceV2,
    input: &Value,
    product: &ProductObservationV2,
    resolve: Resolver<'_>,
) -> VerificationResult<()> {
    let after_release = (evidence.key.family == "C-CANCEL"
        && evidence.key.scenario == "after-release")
        || (evidence.key.family == "C-OWNER" && evidence.key.scenario == "stale-attempt");
    let during_drain = evidence.key.family == "C-CANCEL" && evidence.key.scenario == "during-drain";
    let scenario = if during_drain {
        "during-drain"
    } else if after_release {
        "after-release"
    } else {
        "held-before-release"
    };
    header(input, "memcordon.windows-current-control-case", 1)?;
    fields(
        input,
        &[
            "format",
            "revision",
            "key",
            "run_id",
            "source_commit",
            "source_tree_sha256",
            "lease_id",
            "artifacts",
            "target_fixture",
            "target_fixture_sha256",
            "owner",
            "owner_probe",
            "substitution_launch",
            "drain_artifacts",
        ],
        &[],
    )?;
    if input["key"] != serde_json::to_value(&evidence.key).map_err(|error| error.to_string())?
        || input["run_id"] != evidence.run_id
        || input["source_commit"] != product.source_commit
        || input["source_tree_sha256"] != product.source_tree_sha256
        || input["lease_id"] != product.lifecycle.lease_id
        || evidence.lease_id.as_deref() != Some(product.lifecycle.lease_id.as_str())
        || evidence.retirement != product.lifecycle.receipt
        || evidence.recovery.is_some()
        || evidence.component_recipe_id.is_some()
    {
        return Err("current held cancellation changes selected source/lease".into());
    }
    let path = |role: &str| {
        input["artifacts"][role]
            .as_str()
            .ok_or_else(|| format!("original held cancellation {role} absent"))
    };
    fields(
        &input["artifacts"],
        &[
            "invocation.json",
            "request.json",
            "accepted.json",
            "accepted-ack.json",
            "prepared.json",
            "native-launch.json",
            "cancel.json",
            "native.json",
            "result.json",
            "terminal.json",
            "wait.json",
            "stdout.bin",
            "stderr.bin",
        ],
        if after_release {
            &["prepared-ack.json", "target-started.json"]
        } else {
            &[]
        },
    )?;
    for (role, actual) in [
        ("invocation.json", Some(evidence.invocation.as_str())),
        ("request.json", evidence.request.as_deref()),
        ("prepared.json", evidence.attempt_observation.as_deref()),
        ("result.json", evidence.raw_result.as_deref()),
        ("terminal.json", evidence.authenticated_terminal.as_deref()),
        ("native.json", Some(evidence.native_observation.as_str())),
        ("stdout.bin", Some(evidence.stdout.as_str())),
        ("stderr.bin", Some(evidence.stderr.as_str())),
    ] {
        if actual != Some(path(role)?) {
            return Err("held cancellation changes original artifact role".into());
        }
    }
    let cli = product
        .components
        .iter()
        .find(|component| component.role == "public-cli")
        .ok_or("actual selected CLI absent")?;
    let owner = document(
        input["owner"]
            .as_str()
            .ok_or("original control lease owner absent")?,
        resolve,
    )?;
    header(
        &owner,
        "memcordon.consumer-readiness.windows-lease-owner",
        2,
    )?;
    if owner["identity"]["run_id"] != evidence.run_id
        || owner["identity"]["source_commit"] != product.source_commit
        || owner["identity"]["source_tree_sha256"] != product.source_tree_sha256
        || owner["key"] != serde_json::to_value(&product.key).map_err(|error| error.to_string())?
    {
        return Err("control original owner source/cell differs".into());
    }
    let current = &owner["current"];
    if current["cli"]["sha256"] != cli.installed_sha256
        || current["source_commit"] != product.source_commit
        || current["target"] != product.key.target
        || current["version"] != product.version
        || current["fixture"]["sha256"] != input["target_fixture_sha256"]
    {
        return Err("control original selected bytes differ".into());
    }
    if evidence.fixture_sha256 != cli.installed_sha256
        || crate::sha256(&resolve(&evidence.fixture)?) != cli.installed_sha256
    {
        return Err("held cancellation frontend substitutes selected bytes".into());
    }
    let target_fixture = input["target_fixture"]
        .as_str()
        .ok_or("actual held cancellation fixture absent")?;
    if !evidence.outputs.contains(&target_fixture.to_owned())
        || crate::sha256(&resolve(target_fixture)?) != input["target_fixture_sha256"]
    {
        return Err("held target fixture bytes differ".into());
    }
    let invocation = document(path("invocation.json")?, resolve)?;
    header(
        &invocation,
        "memcordon.windows-current-control-invocation",
        1,
    )?;
    if invocation["scenario"] != scenario
        || invocation["cli_sha256"] != cli.installed_sha256
        || invocation["fixture_sha256"] != input["target_fixture_sha256"]
    {
        return Err("actual held invocation differs".into());
    }
    let directory = format!(
        "{}\\current-controls\\{}",
        current["output_directory"]
            .as_str()
            .ok_or("original control output directory absent")?
            .trim_end_matches(['\\', '/']),
        scenario
    );
    let encode = |text: &str| text.encode_utf16().collect::<Vec<_>>();
    let target_path = current["fixture"]["path"]
        .as_str()
        .ok_or("original target fixture path absent")?;
    let mut expected_args = vec![
        encode("--boundary"),
        encode("sealed"),
        encode("--workload-request"),
        encode(&format!("{directory}\\request.json")),
        encode("--workload-observation-directory"),
        encode(&format!("{directory}\\prepared")),
        encode("--report-format"),
        encode("result-v3"),
        encode("--report"),
        encode(&format!("{directory}\\result.json")),
        encode("--windows-terminal-observation"),
        encode(&format!("{directory}\\terminal.json")),
        encode("--"),
        encode(target_path),
    ];
    let target_args = if after_release {
        vec![
            encode("hold"),
            encode("--duration"),
            encode("240s"),
            encode("--pid-file"),
            encode(&format!("{directory}\\target-started.json")),
        ]
    } else {
        vec![encode("exit"), encode("--code"), encode("0")]
    };
    expected_args.extend(target_args.clone());
    if invocation["program_utf16"]
        != serde_json::to_value(encode(
            current["cli"]["path"]
                .as_str()
                .ok_or("original CLI path absent")?,
        ))
        .map_err(|error| error.to_string())?
        || invocation["cwd_utf16"]
            != serde_json::to_value(encode(&directory)).map_err(|error| error.to_string())?
        || invocation["argv_utf16"]
            != serde_json::to_value(expected_args).map_err(|error| error.to_string())?
        || invocation["work_deadline_unix_millis"] != owner["work_deadline_unix_millis"]
        || invocation["cleanup_deadline_unix_millis"] != owner["cleanup_deadline_unix_millis"]
    {
        return Err("held control command changes original source arguments/cwd/deadlines".into());
    }
    let public = document(path("result.json")?, resolve)?;
    result(&public)?;
    let expected_provider = provider(product, resolve)?;
    if public["provider"] != expected_provider
        || public["release"]
            != if after_release {
                "released"
            } else {
                "not-released"
            }
        || public["cleanup"]["state"] != "complete"
        || public["outcome"]["native_termination"].is_null() == after_release
        || if during_drain {
            ![
                (json!("interrupted"), json!(130)),
                (json!("provider-failure"), json!(125)),
            ]
            .contains(&(
                public["outcome"]["kind"].clone(),
                public["outcome"]["wrapper_status"].clone(),
            ))
        } else {
            public["outcome"]["kind"] != "interrupted" || public["outcome"]["wrapper_status"] != 130
        }
    {
        return Err(
            "held cancellation invents execution, loses interruption or lacks native settlement"
                .into(),
        );
    }
    let sidecar = document(path("terminal.json")?, resolve)?;
    header(&sidecar, "memcordon.windows-terminal-observation", 2)?;
    if sidecar["provider"] != expected_provider {
        return Err("held terminal provider differs".into());
    }
    let terminal = &sidecar["terminal"];
    super::windows_proof::validate_windows_proof_matrix(terminal)?;
    validate_terminal_authority(
        terminal,
        sidecar["terminal_authority_json"]
            .as_str()
            .ok_or("actual held terminal authority absent")?,
        &sidecar["frontend_delivery"],
    )?;
    let raw_launch: Vec<u8> = serde_json::from_value(sidecar["provider_request"].clone())
        .map_err(|error| error.to_string())?;
    if raw_launch != resolve(path("native-launch.json")?)? {
        return Err("native request changed between held preparation and actual terminal".into());
    }
    let launch = crate::validate_json_document(&raw_launch)?;
    super::windows_actors::validate_launch_request(&launch)?;
    let (request, request_digest) = request(&resolve(path("request.json")?)?)?;
    if launch["expected_provider_binding"] != expected_provider
        || launch["workload_request"] != request
        || public["request"]["request_sha256"] != request_digest
    {
        return Err("held request differs from actual sent native request".into());
    }
    let prepared = document(path("prepared.json")?, resolve)?;
    let accepted = document(path("accepted.json")?, resolve)?;
    let accepted_sha256 = accepted_commitment(&accepted)?;
    let accepted_ack = document(path("accepted-ack.json")?, resolve)?;
    validate_control_message(
        &accepted_ack,
        "preparation-acknowledged",
        &accepted,
        Some(&accepted_sha256),
    )?;
    fields(
        &accepted_ack,
        &[
            "message",
            "schema_version",
            "attempt_id",
            "nonce",
            "request_sha256",
            "accepted_sha256",
        ],
        &[],
    )?;
    if accepted["provider"] != expected_provider
        || accepted_ack["message"] != "preparation-acknowledged"
        || accepted_ack["schema_version"] != 4
        || accepted_ack["accepted_sha256"] != accepted_sha256
        || invocation["environment_cleared"] != true
        || invocation["frontend_environment"] != launch["environment"]
    {
        return Err(
            "held preparation changes original acceptance, acknowledgment, or environment".into(),
        );
    }
    for field in ["attempt_id", "nonce", "request_sha256"] {
        if accepted[field] != prepared[field] || accepted_ack[field] != accepted[field] {
            return Err("held preparation acknowledgment crosses original acceptance".into());
        }
    }
    if after_release {
        let ack = document(path("prepared-ack.json")?, resolve)?;
        validate_control_message(
            &ack,
            "prepared-acknowledged",
            &prepared,
            Some(&prepared_commitment(&prepared)?),
        )?;
        fields(
            &ack,
            &[
                "message",
                "schema_version",
                "attempt_id",
                "nonce",
                "request_sha256",
                "prepared_sha256",
            ],
            &[],
        )?;
        if ack["message"] != "prepared-acknowledged"
            || ack["schema_version"] != 4
            || ack["prepared_sha256"] != prepared_commitment(&prepared)?
        {
            return Err("after-release caller lacks actual original Prepared ACK".into());
        }
        for field in ["attempt_id", "nonce", "request_sha256"] {
            if ack[field] != prepared[field] {
                return Err("after-release ACK crosses original target".into());
            }
        }
        let started = resolve(path("target-started.json")?)?;
        let text = std::str::from_utf8(&started).map_err(|error| error.to_string())?;
        let mut fields = text.split_whitespace();
        let pid = fields
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or("actual executed target PID absent")?;
        let birth = fields
            .next()
            .and_then(|value| value.parse::<u64>().ok())
            .ok_or("actual executed target birth absent")?;
        if fields.next().is_some()
            || prepared["target"]["process_id"] != pid
            || prepared["target"]["creation_time_100ns"] != birth
        {
            return Err(
                "after-release target effect differs from original held native identity".into(),
            );
        }
    }
    header(&prepared, "memcordon.windows-workload-prepared", 1)?;
    fields(
        &prepared,
        &[
            "format",
            "revision",
            "attempt_id",
            "nonce",
            "request_sha256",
            "target",
            "owner_manifest_sha256",
        ],
        &[],
    )?;
    fields(
        &prepared["target"],
        &["process_id", "creation_time_100ns"],
        &[],
    )?;
    let cancel = document(path("cancel.json")?, resolve)?;
    fields(
        &cancel,
        &[
            "message",
            "schema_version",
            "attempt_id",
            "nonce",
            "request_sha256",
            "signal",
        ],
        &[],
    )?;
    if cancel["message"] != "cancel" || cancel["schema_version"] != 4 || cancel["signal"] != 2 {
        return Err("actual held cancellation message absent".into());
    }
    for field in ["attempt_id", "nonce", "request_sha256"] {
        if prepared[field] != terminal[field] || cancel[field] != prepared[field] {
            return Err("held cancellation crosses original attempt".into());
        }
    }
    if prepared["request_sha256"] != crate::sha256(&raw_launch)
        || launch["nonce"] != prepared["nonce"]
        || prepared["target"] != terminal["process_observation"]["root_identity"]
        || prepared["owner_manifest_sha256"]
            != terminal["retirement_proof"]["owner_manifest_sha256"]
    {
        return Err("held original target/native request/owner set substituted".into());
    }
    let native = document(path("native.json")?, resolve)?;
    header(&native, "memcordon.windows-current-control-native", 1)?;
    if native["target"] != prepared["target"]
        || if during_drain {
            ![json!(0), json!(258)].contains(&native["target_wait_before_cancel"])
        } else {
            native["target_wait_before_cancel"] != 258
        }
        || native["target_wait_after_cancel"] != 0
        || native["cancel_sha256"] != crate::sha256(&resolve(path("cancel.json")?)?)
    {
        return Err("held original target lacks exact live-before/dead-after native wait".into());
    }
    if native["prepared_sha256"] != prepared_commitment(&prepared)? {
        return Err("prepared native binding differs from original held observation".into());
    }
    if evidence.key.family == "C-OWNER" && evidence.key.scenario == "request-substitution" {
        let probe_path = input["owner_probe"]
            .as_str()
            .ok_or("actual request-substitution probe absent")?;
        let substitute_path = input["substitution_launch"]
            .as_str()
            .ok_or("actual substituted native request operand absent")?;
        if !evidence.outputs.contains(&probe_path.to_owned())
            || !evidence.outputs.contains(&substitute_path.to_owned())
        {
            return Err("current owner probe artifacts absent from own custody".into());
        }
        let probe = document(probe_path, resolve)?;
        header(&probe, "memcordon.windows-current-owner-probe", 1)?;
        fields(
            &probe,
            &[
                "format",
                "revision",
                "scenario",
                "request",
                "response",
                "delivery",
                "target",
                "target_wait_before",
                "target_wait_after",
                "substituted_launch_sha256",
            ],
            &[],
        )?;
        let substituted_bytes = resolve(substitute_path)?;
        let substituted = crate::validate_json_document(&substituted_bytes)?;
        super::windows_actors::validate_launch_request(&substituted)?;
        let mut expected_substitution = launch.clone();
        let arguments = expected_substitution["command"]["arguments"]
            .as_array_mut()
            .ok_or("original native target arguments absent")?;
        *arguments
            .last_mut()
            .ok_or("original native exit code operand absent")? =
            serde_json::to_value("1".encode_utf16().collect::<Vec<_>>())
                .map_err(|error| error.to_string())?;
        if substituted != expected_substitution
            || probe["substituted_launch_sha256"] != crate::sha256(&substituted_bytes)
            || probe["substituted_launch_sha256"] == prepared["request_sha256"]
        {
            return Err(
                "actual owner probe did not substitute exactly the independent request operand"
                    .into(),
            );
        }
        let actual_request = &probe["request"];
        let actual_response = &probe["response"];
        fields(
            actual_request,
            &[
                "message",
                "schema_version",
                "attempt_id",
                "nonce",
                "request_sha256",
                "challenge",
            ],
            &[],
        )?;
        fields(
            actual_response,
            &[
                "kind",
                "schema_version",
                "challenge",
                "attempt_id",
                "detail",
            ],
            &[],
        )?;
        crate::digest(
            actual_request["challenge"]
                .as_str()
                .ok_or("actual native probe challenge absent")?,
        )?;
        if probe["scenario"] != "request-substitution"
            || probe["target"] != prepared["target"]
            || probe["target_wait_before"] != 258
            || probe["target_wait_after"] != 258
            || !probe["delivery"].is_null()
            || actual_request["message"] != "recover-attempt"
            || actual_request["schema_version"] != 4
            || actual_request["attempt_id"] != prepared["attempt_id"]
            || actual_request["nonce"] != prepared["nonce"]
            || actual_request["request_sha256"] != probe["substituted_launch_sha256"]
            || actual_response["kind"] != "recovery-attempt-unavailable"
            || actual_response["schema_version"] != 4
            || actual_response["challenge"] != actual_request["challenge"]
            || actual_response["attempt_id"] != prepared["attempt_id"]
            || actual_response["detail"]
                .as_str()
                .is_none_or(|detail| detail.is_empty() || detail.len() > 4096)
        {
            return Err("request substitution gained native authority, changed original target, or changed actual authenticated response".into());
        }
    } else if evidence.key.family == "C-OWNER" && evidence.key.scenario == "stale-attempt" {
        if !input["substitution_launch"].is_null() {
            return Err("stale attempt substitutes an unrelated launch mutation".into());
        }
        let operation_path = input["owner_probe"]
            .as_str()
            .ok_or("actual prior current attempt probe absent")?;
        if !evidence.outputs.contains(&operation_path.to_owned()) {
            return Err("stale attempt operation was not retained".into());
        }
        let operation = document(operation_path, resolve)?;
        header(
            &operation,
            "memcordon.windows-current-stale-owner-operation",
            1,
        )?;
        fields(
            &operation,
            &[
                "format",
                "revision",
                "prior_prepared_bytes",
                "prior_result_bytes",
                "prior_terminal_bytes",
                "request",
                "response",
                "delivery",
                "target",
                "target_wait_before",
                "target_wait_after",
            ],
            &[],
        )?;
        let decode = |field: &str| -> VerificationResult<Value> {
            let bytes: Vec<u8> = serde_json::from_value(operation[field].clone())
                .map_err(|error| error.to_string())?;
            crate::validate_json_document(&bytes)
        };
        let prior = decode("prior_prepared_bytes")?;
        prepared_commitment(&prior)?;
        let prior_result = decode("prior_result_bytes")?;
        result(&prior_result)?;
        let prior_sidecar = decode("prior_terminal_bytes")?;
        header(&prior_sidecar, "memcordon.windows-terminal-observation", 2)?;
        let prior_terminal = &prior_sidecar["terminal"];
        super::windows_proof::validate_windows_proof_matrix(prior_terminal)?;
        validate_terminal_authority(
            prior_terminal,
            prior_sidecar["terminal_authority_json"]
                .as_str()
                .ok_or("prior native terminal authority absent")?,
            &prior_sidecar["frontend_delivery"],
        )?;
        let retired = &operation["response"];
        if terminal_retired_digest(retired)? != prior_sidecar["frontend_delivery"]["retired_sha256"]
            || terminal_proof_digest(
                prior_sidecar["terminal_authority_json"]
                    .as_str()
                    .ok_or("prior exact terminal authority absent")?,
            )? != retired["retirement_proof_sha256"]
        {
            return Err("stale retirement changed exact original native ACK or proof bytes".into());
        }
        fields(
            retired,
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
        let recovery = &operation["request"];
        fields(
            recovery,
            &[
                "message",
                "schema_version",
                "attempt_id",
                "nonce",
                "request_sha256",
                "challenge",
            ],
            &[],
        )?;
        crate::digest(
            recovery["challenge"]
                .as_str()
                .ok_or("stale native recovery challenge absent")?,
        )?;
        for field in ["attempt_id", "nonce", "request_sha256"] {
            if retired[field] != prior[field]
                || recovery[field] != prior[field]
                || prior_terminal[field] != prior[field]
            {
                return Err(
                    "stale operation does not retain original prior current association".into(),
                );
            }
        }
        for field in [
            "job_identity",
            "owner_manifest_sha256",
            "original_boot_id",
            "launch_incarnation",
        ] {
            if retired[field] != prior_terminal["retirement_proof"][field] {
                return Err("stale retirement native owner differs from actual prior proof".into());
            }
        }
        if prior["attempt_id"] == prepared["attempt_id"]
            || prior["nonce"] == prepared["nonce"]
            || operation["target"] != prepared["target"]
            || operation["target_wait_before"] != 258
            || operation["target_wait_after"] != 258
            || !operation["delivery"].is_null()
            || recovery["message"] != "recover-attempt"
            || recovery["schema_version"] != 4
            || retired["kind"] != "terminal-retired-v2"
            || retired["schema_version"] != 2
            || retired["completion"] != "retirement-complete"
            || retired["disposition"] != "posttarget"
            || retired["provider_generation"] != expected_provider["generation"]
            || prior_sidecar["provider"] != expected_provider
            || prior_result["provider"] != expected_provider
            || prior_result["cleanup"]["state"] != "complete"
            || prior_result["release"] != "not-released"
            || !prior_result["outcome"]["native_termination"].is_null()
            || prior_result["runtime"]["native"]["retirement"] != prior_terminal["retirement_proof"]
            || prior_result["runtime"]["native"]["frontend_delivery"]
                != prior_sidecar["frontend_delivery"]
            || retired["terminal_response_sha256"]
                != prior_sidecar["frontend_delivery"]["terminal_sha256"]
        {
            return Err("stale current owner acquired fresh authority or lost original complete native retirement".into());
        }
        for field in ["retirement_proof_sha256", "ledger_generation"] {
            crate::digest(
                retired[field]
                    .as_str()
                    .ok_or("stale retirement digest absent")?,
            )?;
        }
    } else if evidence.key.family == "C-OWNER" && evidence.key.scenario.starts_with("foreign-") {
        if !input["substitution_launch"].is_null() {
            return Err("foreign actor substitutes another case's launch mutation".into());
        }
        let probe_path = input["owner_probe"]
            .as_str()
            .ok_or("actual foreign owner operation absent")?;
        if !evidence.outputs.contains(&probe_path.to_owned()) {
            return Err("foreign native operation outside retained source artifacts".into());
        }
        let operation = document(probe_path, resolve)?;
        header(
            &operation,
            "memcordon.windows-current-foreign-owner-operation",
            1,
        )?;
        fields(
            &operation,
            &[
                "format",
                "revision",
                "scenario",
                "program_utf16",
                "argv_utf16",
                "native_status",
                "stdout_bytes",
                "stderr_bytes",
                "original_token_status",
                "original_token_stdout",
                "original_token_stderr",
                "target",
                "target_wait_before",
                "target_wait_after",
            ],
            &[],
        )?;
        let bytes = |value: &Value| -> VerificationResult<Vec<u8>> {
            serde_json::from_value(value.clone()).map_err(|error| error.to_string())
        };
        let raw = bytes(&operation["stdout_bytes"])?;
        if raw.len() > 256 * 1024 {
            return Err("foreign actual native reply exceeds bounded capture".into());
        }
        let probe = crate::validate_json_document(&raw)?;
        header(&probe, "memcordon.windows-current-foreign-owner-probe", 1)?;
        fields(
            &probe,
            &[
                "format",
                "revision",
                "process_id",
                "token",
                "request",
                "response_bytes",
                "exchange_error",
            ],
            &[],
        )?;
        let original_token =
            crate::validate_json_document(&bytes(&operation["original_token_stdout"])?)?;
        for token in [&original_token, &probe["token"]] {
            fields(
                token,
                &[
                    "user_sid",
                    "restricted",
                    "integrity_rid",
                    "elevated",
                    "restricting_sids",
                ],
                &[],
            )?;
        }
        let foreign_pid = probe["process_id"]
            .as_u64()
            .filter(|pid| *pid > 0 && *pid <= u64::from(u32::MAX))
            .ok_or("actual foreign token process absent")?;
        if probe["token"]["restricted"] != true
            || original_token["restricted"] != false
            || probe["token"]["user_sid"] != original_token["user_sid"]
            || probe["token"]["restricting_sids"]
                .as_array()
                .is_none_or(Vec::is_empty)
            || operation["native_status"] != 0
            || operation["original_token_status"] != 0
            || !bytes(&operation["stderr_bytes"])?.is_empty()
            || !bytes(&operation["original_token_stderr"])?.is_empty()
            || operation["scenario"] != evidence.key.scenario
            || operation["target"] != prepared["target"]
            || operation["target_wait_before"] != 258
            || operation["target_wait_after"] != 258
            || native["frontend"]["process_id"] == foreign_pid
        {
            return Err("foreign actor lacks actual distinct restricted token floor, native wait, or original held target".into());
        }
        let actual_request = &probe["request"];
        let expected_request = match evidence.key.scenario.as_str() {
            "foreign-inspect" => {
                json!({"message":"replay-terminal","schema_version":4,"attempt_id":prepared["attempt_id"],"nonce":prepared["nonce"],"request_sha256":prepared["request_sha256"],"relay_phase":"await-terminal"})
            }
            "foreign-cancel" => {
                json!({"message":"cancel","schema_version":4,"attempt_id":prepared["attempt_id"],"nonce":prepared["nonce"],"request_sha256":prepared["request_sha256"],"signal":2})
            }
            "foreign-recover" => {
                let challenge = crate::sha256(
                    format!(
                        "memcordon.current-owner-probe\0{}\0{}",
                        prepared["nonce"].as_str().ok_or("original nonce missing")?,
                        evidence.key.scenario
                    )
                    .as_bytes(),
                );
                json!({"message":"recover-attempt","schema_version":4,"attempt_id":prepared["attempt_id"],"nonce":prepared["nonce"],"request_sha256":prepared["request_sha256"],"challenge":challenge})
            }
            _ => return Err("unknown foreign owner operation".into()),
        };
        let expected_argv = vec![
            encode("consumer-readiness-windows"),
            encode("restricted-frontend"),
            encode(target_path),
            encode("consumer-readiness-windows"),
            encode("owner-request-probe"),
        ];
        let actual_argv: Vec<Vec<u16>> = serde_json::from_value(operation["argv_utf16"].clone())
            .map_err(|error| error.to_string())?;
        if actual_request != &expected_request
            || operation["program_utf16"] != json!(encode(target_path))
            || actual_argv.len() != expected_argv.len() + 1
            || actual_argv[..expected_argv.len()] != expected_argv
        {
            return Err(
                "foreign native process command or request does not name actual original attempt"
                    .into(),
            );
        }
        let argument =
            String::from_utf16(actual_argv.last().unwrap()).map_err(|error| error.to_string())?;
        if crate::validate_json_document(argument.as_bytes())? != expected_request {
            return Err(
                "foreign native command argument differs from observed sent request".into(),
            );
        }
        if probe["response_bytes"].is_null() {
            if probe["exchange_error"].as_str().is_none_or(|error| {
                !error.starts_with("response: PeerClosed(") || error.len() > 4096
            }) {
                return Err("foreign actor did not reach the authenticated current provider request handler".into());
            }
        } else {
            if !probe["exchange_error"].is_null() {
                return Err("foreign actor claims both reply and exchange failure".into());
            }
            let response = crate::validate_json_document(&bytes(&probe["response_bytes"])?)?;
            match response["kind"].as_str() {
                Some("recovery-attempt-unavailable")
                    if evidence.key.scenario == "foreign-recover"
                        && response["schema_version"] == 4
                        && response["attempt_id"] == prepared["attempt_id"]
                        && response["challenge"] == expected_request["challenge"] => {}
                Some("replay-unavailable")
                    if evidence.key.scenario == "foreign-inspect"
                        && response["attempt_id"] == prepared["attempt_id"] => {}
                _ => {
                    return Err(
                        "foreign actor gained native authority or captured unrelated response"
                            .into(),
                    );
                }
            }
        }
    } else if !input["owner_probe"].is_null() || !input["substitution_launch"].is_null() {
        return Err("held cancellation substitutes another case's owner probe".into());
    }
    if during_drain {
        validate_drain_case(
            &input["drain_artifacts"],
            &owner,
            &prepared,
            &native,
            &cancel,
            &directory,
            evidence,
            resolve,
        )?;
    } else if input["drain_artifacts"] != json!({}) {
        return Err("non-drain case invents current package operation".into());
    }
    let payload = &terminal["payload"];
    if after_release
        && (payload["outcome"]["child_after_termination"].is_null()
            || public["outcome"]["native_termination"]
                != payload["outcome"]["child_after_termination"])
    {
        return Err("after-release result differs from actual native direct target wait".into());
    }
    let boundary = &payload["boundary_detail"];
    let native_boundary = boundary;
    validate_prepared_boundary(native_boundary)?;
    yes(
        native_boundary,
        &[
            "terminate_job_invoked",
            "active_processes_zero",
            "direct_target_reaped",
            "relays_retired",
            "guardian_reaped",
            "final_job_handles_closed",
        ],
    )?;
    if payload["kind"] != "execution"
        || if during_drain {
            ![json!("interrupted"), json!("monitor-failed")]
                .contains(&payload["outcome"]["outcome"])
        } else {
            payload["outcome"]["outcome"] != "interrupted"
                || payload["outcome"]["signal"]["signal"] != 2
        }
        || boundary["mechanism"] != "windows-job-object-v3"
        || native_boundary["target_released"] != after_release
        || native_boundary["target_created_suspended"] != true
    {
        return Err("held native cancellation was resumed or lost actual cleanup outcome".into());
    }
    if during_drain {
        if payload["outcome"]["outcome"] == "interrupted" {
            if payload["outcome"]["signal"]["signal"] != 2
                || public["outcome"]["kind"] != "interrupted"
                || public["outcome"]["wrapper_status"] != 130
            {
                return Err("drain cancellation changed actual interrupted outcome".into());
            }
        } else {
            let authority = crate::validate_json_document(
                sidecar["terminal_authority_json"]
                    .as_str()
                    .ok_or("actual drain native authority absent")?
                    .as_bytes(),
            )?;
            let mut immutable_rejection = public["windows_rejection"].clone();
            if !immutable_rejection["loader_qualification"].is_null() {
                return Err("unresumed drain target claims executed loader qualification".into());
            }
            let rejection_object = immutable_rejection
                .as_object_mut()
                .ok_or("actual drain rejection projection absent")?;
            rejection_object.remove("provider_failure");
            rejection_object.remove("guardian_causal_receipt");
            if public["outcome"]["kind"] != "provider-failure"
                || public["outcome"]["wrapper_status"] != 125
                || authority["kind"] != "reject"
                || immutable_rejection != authority["rejection"]
                || public["provider_failure"] != public["windows_rejection"]["provider_failure"]
            {
                return Err(
                    "drain replaced original native failure with fabricated cancellation outcome"
                        .into(),
                );
            }
        }
    }
    let mut actual_boundary = boundary.clone();
    actual_boundary
        .as_object_mut()
        .ok_or("held native boundary absent")?
        .remove("mechanism");
    let mut projected = public["runtime"]["native"].clone();
    for field in [
        "frontend_delivery",
        "frontend_provider_association",
        "retirement",
    ] {
        actual_boundary.as_object_mut().unwrap().remove(field);
        projected
            .as_object_mut()
            .ok_or("held result current native facts absent")?
            .remove(field);
    }
    validate_public_windows_association(&public, terminal, &expected_provider)?;
    fields(&public["runtime"], &["kind", "profile", "native"], &[])?;
    if public["runtime"]["kind"] != "windows-sealed"
        || public["runtime"]["profile"] != "windows-sealed-current-token-v1"
        || actual_boundary != projected
        || public["runtime"]["native"]["retirement"] != terminal["retirement_proof"]
        || public["runtime"]["native"]["frontend_delivery"] != sidecar["frontend_delivery"]
    {
        return Err("held result changes actual terminal retirement or native facts".into());
    }
    let frontend_pid = native["frontend"]["process_id"]
        .as_u64()
        .and_then(|pid| u32::try_from(pid).ok())
        .filter(|pid| *pid != 0)
        .ok_or("original held frontend PID absent")?;
    let frontend_birth = native["frontend"]["creation_time_100ns"]
        .as_u64()
        .ok_or("original held frontend birth absent")?;
    let mut actual_attempt = sha2::Sha256::new();
    actual_attempt.update(
        prepared["nonce"]
            .as_str()
            .ok_or("prepared nonce absent")?
            .as_bytes(),
    );
    actual_attempt.update(frontend_pid.to_le_bytes());
    actual_attempt.update(frontend_birth.to_le_bytes());
    actual_attempt.update(crate::sha256(&raw_launch).as_bytes());
    if hex::encode(actual_attempt.finalize()) != prepared["attempt_id"] {
        return Err("held prepared attempt does not belong to original frontend process".into());
    }
    let native_command = &launch["command"];
    if launch["policy"]
        != json!({"memory_limit_bytes":null,"absolute_deadline_millis":null,"lifetime":"command","poll_interval_millis":50,"signal_grace_millis":2000,"command_exit_grace_millis":0,"limit_grace_millis":0})
        || public["request"]["resource_policy_sha256"] != resources::default_resource_digest()
    {
        return Err("held native limits or requested-resource commitment changed".into());
    }
    let mut args = vec![
        serde_json::from_value::<Vec<u16>>(native_command["program"].clone())
            .map_err(|error| error.to_string())?,
    ];
    args.extend(
        serde_json::from_value::<Vec<Vec<u16>>>(native_command["arguments"].clone())
            .map_err(|error| error.to_string())?,
    );
    let arguments = crate::NativeArguments::WindowsUtf16(args.clone());
    crate::wire::validate_arguments(&arguments, &evidence.key.target)?;
    if public["request"]["invocation_sha256"]
        != crate::wire::invocation_digest_parts(&arguments, &[], &None, &None)?
    {
        return Err("held current invocation commitment differs".into());
    }
    let expected_argv = args
        .iter()
        .map(|units| {
            String::from_utf16(units)
                .map(|display| json!({"display":display,"raw":null}))
                .map_err(|error| error.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if public["invocation"]
        != json!({"syntax":"plus-budgets-v1","budget_tokens":[],"memory_token":null,"deadline_token":null,"argv":expected_argv})
        || args[1..] != target_args
    {
        return Err("held target argv/source fixture mode differs".into());
    }
    let stdout = resolve(&evidence.stdout)?;
    let stderr = resolve(&evidence.stderr)?;
    let wait = document(path("wait.json")?, resolve)?;
    header(&wait, "memcordon.windows-current-control-wait", 1)?;
    if !stdout.is_empty()
        || wait["native_status"] != public["outcome"]["wrapper_status"]
        || wait["stdout_sha256"] != crate::sha256(&stdout)
        || wait["stderr_sha256"] != crate::sha256(&stderr)
    {
        return Err("held cancellation native frontend wait/raw streams differ".into());
    }
    Ok(())
}

fn validate_interrupted_current(
    phase: &Value,
    owner: &Value,
    provider: &Value,
    product: &ProductObservationV2,
    recovery: &Value,
    directory: &str,
    evidence: &CaseEvidenceV2,
    resolve: Resolver<'_>,
) -> VerificationResult<()> {
    let current = &owner["current"];
    let value = &phase["interrupted"];
    fields(
        value,
        &[
            "path",
            "image_sha256",
            "requested_share_mode",
            "original_file_identity",
            "observed_file_identity",
            "journal_path",
            "journal_sha256",
            "journal_format",
            "journal_revision",
            "journal_operation",
            "runtime_manifest",
            "artifact_digests",
            "replacement_manifest",
            "replacement_artifact_digests",
            "service_observations",
        ],
        &[],
    )?;
    if value["path"] != current["installed_agent"]["path"]
        || value["image_sha256"] != current["agent"]["sha256"]
        || value["requested_share_mode"] != 1
        || value["original_file_identity"] != value["observed_file_identity"]
        || phase["journal_absent"] != true
    {
        return Err("interrupted current replacement lost original native image sharing/identity or recovery".into());
    }
    let identity = value["original_file_identity"]
        .as_array()
        .filter(|identity| identity.len() == 2)
        .ok_or("interrupted exact held image identity absent")?;
    if identity[0]
        .as_u64()
        .is_none_or(|value| value > u64::from(u32::MAX))
        || identity[1].as_u64().is_none()
    {
        return Err("interrupted original native image identity invalid".into());
    }
    let root = owner["binary_root"]
        .as_str()
        .ok_or("interrupted actual managed root absent")?;
    if value["journal_path"].as_str().is_none_or(|path| {
        path.replace('/', "\\")
            != format!(
                "{}\\current-package-state.rollback.json",
                root.trim_end_matches(['\\', '/'])
            )
            .replace('/', "\\")
    }) || value["journal_format"] != "memcordon.windows-current-package-state"
        || value["journal_revision"] != 1
        || value["journal_operation"] != "upgrade"
    {
        return Err("interrupted stage lacks sole current package journal".into());
    }
    crate::digest(
        value["journal_sha256"]
            .as_str()
            .ok_or("actual current journal digest absent")?,
    )?;
    for field in ["runtime_manifest", "replacement_manifest"] {
        if crate::sha256(&bytes_json(&value[field])?) != provider["runtime_manifest_sha256"] {
            return Err(
                "interrupted current journal names different source or package bytes".into(),
            );
        }
    }
    let mut expected_digests = serde_json::Map::new();
    for (field, role) in [
        ("agent_sha256", "sealed-agent"),
        (
            "target_desktop_bootstrap_sha256",
            "target-desktop-bootstrap",
        ),
        ("session_broker_sha256", "session-broker"),
    ] {
        let component = product
            .components
            .iter()
            .find(|component| component.role == role)
            .ok_or("interrupted exact measured component absent")?;
        expected_digests.insert(field.into(), json!(component.installed_sha256));
    }
    for field in ["artifact_digests", "replacement_artifact_digests"] {
        if value[field] != Value::Object(expected_digests.clone()) {
            return Err("interrupted current rollback substitutes component bytes".into());
        }
    }
    let mut services = BTreeSet::new();
    for service in value["service_observations"]
        .as_array()
        .ok_or("actual interrupted SCM stage absent")?
    {
        if service["api"] != "OpenServiceW"
            || service["native_domain"] != "win32"
            || service["native_code"] != 1060
            || !services.insert(
                service["service_name"]
                    .as_str()
                    .ok_or("actual interrupted service name absent")?
                    .to_owned(),
            )
        {
            return Err("interrupted package did not reach native service retirement".into());
        }
    }
    let mut expected_services = (0..8)
        .map(|index| format!("MemCordonSealedGuardian-{index:03}"))
        .collect::<BTreeSet<_>>();
    expected_services.extend(
        [
            "MemCordonSealedControl",
            "MemCordonSealedLauncher",
            "MemCordonSealedSessionBroker",
        ]
        .map(str::to_owned),
    );
    if services != expected_services {
        return Err("interrupted stage did not actually remove original current services".into());
    }
    let recovered = &phase["recovered"];
    if recovered["source_commit"] != product.source_commit
        || recovered["target"] != product.key.target
        || recovered["version"] != product.version
        || recovered["agent"] != current["agent"]
        || recovered["provider"] != current["provider"]
    {
        return Err("interrupted recovery changed selected current source".into());
    }
    let mut expected_readback = BTreeMap::new();
    for field in ["installed_agent", "installed_manifest"] {
        expected_readback.insert(
            current[field]["path"]
                .as_str()
                .ok_or("current installed path absent")?
                .to_owned(),
            current[field]["sha256"].clone(),
        );
    }
    for component in current["installed_components"]
        .as_array()
        .ok_or("current installed component inventory absent")?
    {
        expected_readback.insert(
            component["path"]
                .as_str()
                .ok_or("current component path absent")?
                .to_owned(),
            component["sha256"].clone(),
        );
    }
    if phase["recovered_artifacts"]
        != serde_json::to_value(expected_readback).map_err(|error| error.to_string())?
    {
        return Err(
            "interrupted recovery did not independently read every current installed artifact"
                .into(),
        );
    }
    let recovery_directory = format!("{directory}\\recovery");
    let mut required = Vec::new();
    for operation in ["upgrade", "verify"] {
        for leaf in [
            "invocation.json",
            "capture.json",
            "stdout.bin",
            "stderr.bin",
        ] {
            required.push(format!("package-{operation}.{leaf}"));
        }
    }
    let refs = required.iter().map(String::as_str).collect::<Vec<_>>();
    fields(recovery, &refs, &[])?;
    for path in recovery.as_object().unwrap().values() {
        let path = path
            .as_str()
            .ok_or("original recovery artifact reference absent")?;
        if !evidence.outputs.contains(&path.to_owned()) {
            return Err("current recovery artifact outside retained source operation".into());
        }
        resolve(path)?;
    }
    for operation in ["upgrade", "verify"] {
        let artifact = |leaf: &str| {
            recovery[format!("package-{operation}.{leaf}")]
                .as_str()
                .ok_or_else(|| "current recovery native artifact absent".to_owned())
        };
        let invocation = document(artifact("invocation.json")?, resolve)?;
        let capture = document(artifact("capture.json")?, resolve)?;
        validate_package_command(
            &invocation,
            &capture,
            operation,
            current["agent"]["path"]
                .as_str()
                .ok_or("current recovery executable absent")?,
            &recovery_directory,
            current["agent"]["sha256"]
                .as_str()
                .ok_or("current recovery executable digest absent")?,
        )?;
    }
    Ok(())
}

fn validate_opaque_refusal(
    value: &Value,
    owner: &Value,
    provider: &Value,
) -> VerificationResult<()> {
    fields(
        value,
        &[
            "path",
            "root",
            "expected_bytes",
            "observed_bytes",
            "original_file_identity",
            "observed_file_identity",
            "original_root_identity",
            "observed_root_identity",
            "native_before_bytes",
            "native_after_bytes",
        ],
        &[],
    )?;
    let root = owner["binary_root"]
        .as_str()
        .ok_or("original opaque root absent")?;
    let expected = [
        b"\0opaque current install input\xff\0".as_slice(),
        provider["generation"]
            .as_str()
            .ok_or("actual provider generation absent")?
            .as_bytes(),
    ]
    .concat();
    if value["root"] != root
        || value["path"].as_str().is_none_or(|path| {
            path.replace('/', "\\")
                != format!(
                    "{}\\opaque-current-install-probe.bin",
                    root.trim_end_matches(['\\', '/'])
                )
                .replace('/', "\\")
        })
        || bytes_json(&value["expected_bytes"])? != expected
        || bytes_json(&value["observed_bytes"])? != expected
    {
        return Err("opaque current state bytes/path were replaced or interpreted".into());
    }
    for (original, observed) in [
        ("original_file_identity", "observed_file_identity"),
        ("original_root_identity", "observed_root_identity"),
    ] {
        let identity = value[original]
            .as_array()
            .filter(|identity| identity.len() == 2)
            .ok_or("original held opaque native file identity absent")?;
        if identity[0]
            .as_u64()
            .is_none_or(|value| value > u64::from(u32::MAX))
            || identity[1].as_u64().is_none()
            || value[original] != value[observed]
        {
            return Err("opaque original native file/root identity changed".into());
        }
    }
    let current = &owner["current"];
    let mut expected_paths = ["binary_root", "state_root", "diagnostics_root"]
        .into_iter()
        .map(|field| {
            owner[field]
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| "original package root absent".to_owned())
        })
        .collect::<VerificationResult<BTreeSet<_>>>()?;
    for field in ["installed_agent", "installed_manifest"] {
        expected_paths.insert(
            current[field]["path"]
                .as_str()
                .ok_or("original installed path absent")?
                .into(),
        );
    }
    for component in current["installed_components"]
        .as_array()
        .ok_or("original installed components absent")?
    {
        expected_paths.insert(
            component["path"]
                .as_str()
                .ok_or("original component path absent")?
                .into(),
        );
    }
    let mut expected_services = (0..8)
        .map(|index| format!("MemCordonSealedGuardian-{index:03}"))
        .collect::<BTreeSet<_>>();
    expected_services.extend(
        [
            "MemCordonSealedControl",
            "MemCordonSealedLauncher",
            "MemCordonSealedSessionBroker",
        ]
        .map(str::to_owned),
    );
    for field in ["native_before_bytes", "native_after_bytes"] {
        let removal = crate::validate_json_document(&bytes_json(&value[field])?)?;
        header(&removal, "memcordon.windows-native-removal", 2)?;
        if removal["provider_generation"] != provider["generation"]
            || removal["fixture_processes_absent"] != true
            || removal["installed_image_processes_absent"] != true
        {
            return Err("opaque lifecycle lacked actual native process absence".into());
        }
        let mut services = BTreeSet::new();
        for service in removal["service_observations"]
            .as_array()
            .ok_or("opaque actual SCM observations absent")?
        {
            if service["api"] != "OpenServiceW"
                || service["native_domain"] != "win32"
                || service["native_code"] != 1060
                || !services.insert(
                    service["service_name"]
                        .as_str()
                        .ok_or("opaque native service name absent")?
                        .to_owned(),
                )
            {
                return Err("opaque actual service absence was not observed".into());
            }
        }
        if services != expected_services {
            return Err("opaque actual SCM inventory differs".into());
        }
        let mut paths = BTreeSet::new();
        for observation in removal["path_observations"]
            .as_array()
            .ok_or("opaque native path readback absent")?
        {
            if observation["native_domain"] != "win32"
                || ![Some(2), Some(3)].contains(&observation["native_code"].as_u64())
                || !paths.insert(
                    observation["path"]
                        .as_str()
                        .ok_or("opaque native path absent")?
                        .to_owned(),
                )
            {
                return Err("opaque package absence did not use actual named native errors".into());
            }
        }
        if paths != expected_paths {
            return Err(
                "opaque native absence inventory differs from original current package".into(),
            );
        }
        let census = &removal["native_component_census"];
        if census["api"] != "CreateToolhelp32Snapshot/Process32FirstW/Process32NextW"
            || census["terminal_native_code"] != 18
            || census["matching_processes"] != json!([])
            || census["required_image_names_utf16"]
                .as_array()
                .is_none_or(|names| names.len() != 3)
        {
            return Err("opaque actual current component process census differs".into());
        }
    }
    Ok(())
}

fn package_case(
    evidence: &CaseEvidenceV2,
    input: &Value,
    product: &ProductObservationV2,
    resolve: Resolver<'_>,
) -> VerificationResult<()> {
    let (phase_operation, operation, fresh) =
        match (evidence.key.family.as_str(), evidence.key.scenario.as_str()) {
            ("C-PACKAGE", "fresh-install")
            | ("C-INSTALL-CURRENT", "fresh-without-registry")
            | ("W-PACKAGE", "install")
            | ("W-PACKAGE", "materialize") => {
                ("actual-selected-current-fresh-install", "install", true)
            }
            ("C-INSTALL-CURRENT", "opaque-state-refused") => {
                ("actual-opaque-current-state-refusal", "install", false)
            }
            ("C-INSTALL-CURRENT", "interrupted-current-install") => {
                ("actual-interrupted-current-install", "upgrade", false)
            }
            ("C-PACKAGE", "verify") | ("W-PACKAGE", "verify") => {
                ("actual-selected-current-fresh-verification", "verify", true)
            }
            ("C-PACKAGE", "upgrade")
            | ("W-UPGRADE", "upgrade")
            | ("C-INSTALL-CURRENT", "current-reinstall") => {
                ("actual-current-upgrade", "upgrade", false)
            }
            ("C-PACKAGE", "final-uninstall")
            | ("W-UPGRADE", "uninstall")
            | ("C-INSTALL-CURRENT", "owned-current-uninstall") => {
                ("actual-package-and-native-removal", "uninstall", false)
            }
            ("W-PACKAGE", "component-measure") => {
                ("actual-installed-package-readback", "upgrade", false)
            }
            ("W-UPGRADE", "verify") => (
                "actual-selected-current-upgraded-verification",
                "verify",
                false,
            ),
            ("W-UPGRADE", "recover") | ("C-INSTALL-CURRENT", "current-recovery") => {
                ("actual-owned-native-recovery", "recover", false)
            }
            _ => return Err("unknown selected Windows package obligation".into()),
        };
    header(input, "memcordon.windows-package-case", 1)?;
    fields(
        input,
        &[
            "format",
            "revision",
            "key",
            "run_id",
            "source_commit",
            "source_tree_sha256",
            "lease_id",
            "phase_operation",
            "operation",
            "owner",
            "journal",
            "phase",
            "capture",
            "recovery_artifacts",
        ],
        &[],
    )?;
    if input["key"] != serde_json::to_value(&evidence.key).map_err(|error| error.to_string())?
        || input["run_id"] != evidence.run_id
        || input["source_commit"] != product.source_commit
        || input["source_tree_sha256"] != product.source_tree_sha256
        || input["lease_id"] != product.lifecycle.lease_id
        || evidence.lease_id.as_deref() != Some(&product.lifecycle.lease_id)
        || input["phase_operation"] != phase_operation
        || input["operation"] != operation
        || evidence.request.is_some()
        || evidence.raw_result.is_some()
        || evidence.attempt_observation.is_some()
        || evidence.authenticated_terminal.is_some()
        || evidence.recovery.is_some()
        || evidence.component_recipe_id.is_some()
    {
        return Err("package case invents workload execution or crosses source/lease".into());
    }
    let path = |field: &str| {
        input[field]
            .as_str()
            .ok_or_else(|| format!("package {field} reference absent"))
    };
    let owner = document(path("owner")?, resolve)?;
    header(
        &owner,
        "memcordon.consumer-readiness.windows-lease-owner",
        2,
    )?;
    if owner["identity"]["run_id"] != evidence.run_id
        || owner["identity"]["source_commit"] != product.source_commit
        || owner["identity"]["source_tree_sha256"] != product.source_tree_sha256
        || owner["key"] != serde_json::to_value(&product.key).map_err(|error| error.to_string())?
    {
        return Err("package original owner source/cell differs".into());
    }
    let current = &owner["current"];
    if current["source_commit"] != product.source_commit
        || current["target"] != product.key.target
        || current["version"] != product.version
    {
        return Err("package selected current payload differs".into());
    }
    let agent = product
        .components
        .iter()
        .find(|component| component.role == "sealed-agent")
        .ok_or("measured package agent absent")?;
    let recovery = operation == "recover";
    let executing = if recovery {
        product
            .components
            .iter()
            .find(|component| component.role == "public-cli")
            .ok_or("selected recovery public CLI absent")?
    } else {
        agent
    };
    if evidence.fixture_sha256 != executing.installed_sha256
        || crate::sha256(&resolve(&evidence.fixture)?) != executing.installed_sha256
        || current[if recovery { "cli" } else { "agent" }]["sha256"] != executing.installed_sha256
    {
        return Err("package command does not execute actual measured selected agent".into());
    }
    let journal_bytes = resolve(path("journal")?)?;
    if journal_bytes != resolve(&product.lifecycle.journal)? {
        return Err("package case changes original protected lifecycle journal".into());
    }
    let journal = crate::validate_json_document(&journal_bytes)?;
    let events = journal["events"]
        .as_array()
        .ok_or("package journal events absent")?;
    let matches = events
        .iter()
        .filter(|event| event["operation"] == phase_operation)
        .collect::<Vec<_>>();
    if matches.len() != 1 || matches[0]["succeeded"] != true {
        return Err("actual selected package operation absent, repeated or failed".into());
    }
    let phase_bytes = resolve(path("phase")?)?;
    if crate::sha256(&phase_bytes)
        != crate::sha256(&resolve(
            matches[0]["native_receipt"]
                .as_str()
                .ok_or("journal native phase absent")?,
        )?)
        || evidence.native_observation != path("phase")?
    {
        return Err("package native phase changes original journal capture".into());
    }
    let phase = crate::validate_json_document(&phase_bytes)?;
    if phase_operation != "actual-installed-package-readback" {
        if phase["subject"]["source_commit"] != product.source_commit
            || phase["subject"]["target"] != product.key.target
            || phase["subject"]["version"] != product.version
            || phase["subject"]["agent"]["sha256"] != agent.installed_sha256
            || phase["operation"] != if recovery { "uninstall" } else { operation }
            || (!recovery
                && !["opaque-state-refused", "interrupted-current-install"]
                    .contains(&evidence.key.scenario.as_str())
                && phase["result"] != json!({"Ok":null}))
        {
            return Err("package phase substitutes older payload or failed operation".into());
        }
    } else if phase["binaries"].as_array().is_none_or(Vec::is_empty) {
        return Err("selected current installed component readback absent".into());
    }
    let capture = document(path("capture")?, resolve)?;
    let invocation = document(&evidence.invocation, resolve)?;
    let current_output = current["output_directory"]
        .as_str()
        .ok_or("selected current output directory absent")?;
    let opaque = evidence.key.family == "C-INSTALL-CURRENT"
        && evidence.key.scenario == "opaque-state-refused";
    let interrupted = evidence.key.family == "C-INSTALL-CURRENT"
        && evidence.key.scenario == "interrupted-current-install";
    let directory = if opaque || interrupted {
        format!(
            "{}\\{}",
            current_output.trim_end_matches(['\\', '/']),
            evidence.key.scenario
        )
    } else if fresh {
        format!(
            "{}\\selected-fresh-lifetime",
            current_output.trim_end_matches(['\\', '/'])
        )
    } else {
        current_output.to_owned()
    };
    if recovery {
        validate_native_recovery_phase(
            &invocation,
            &capture,
            &resolve(&evidence.stdout)?,
            &current["cli"],
            &provider(product, resolve)?,
            current_output,
        )?;
    } else {
        validate_package_command_status(
            &invocation,
            &capture,
            operation,
            current["agent"]["path"]
                .as_str()
                .ok_or("actual selected package executable absent")?,
            &directory,
            &agent.installed_sha256,
            if opaque || interrupted { 125 } else { 0 },
        )?;
    }
    if opaque {
        validate_opaque_refusal(&phase["opaque"], &owner, &provider(product, resolve)?)?;
        let stderr = resolve(&evidence.stderr)?;
        if !String::from_utf8_lossy(&stderr).contains("MCSEALED-WINDOWS-ALREADY-INSTALLED")
            || phase["result"]["Err"].as_str().is_none_or(str::is_empty)
        {
            return Err("opaque install did not actually refuse occupied current state".into());
        }
    }
    if interrupted {
        validate_interrupted_current(
            &phase,
            &owner,
            &provider(product, resolve)?,
            product,
            &input["recovery_artifacts"],
            &directory,
            evidence,
            resolve,
        )?;
        if !String::from_utf8_lossy(&resolve(&evidence.stderr)?)
            .contains("MCSEALED-WINDOWS-UPGRADE-ROLLBACK-FAILED")
            || phase["result"]["Err"].as_str().is_none_or(str::is_empty)
        {
            return Err("current replacement did not reach actual interrupted native stage".into());
        }
    } else if input["recovery_artifacts"] != json!({}) {
        return Err("ordinary package row invents recovery operands".into());
    }
    resolve(&evidence.stdout)?;
    resolve(&evidence.stderr)?;
    if resolve(&evidence.retirement)? != resolve(&product.lifecycle.receipt)? {
        return Err("package row replaces original final retirement".into());
    }
    verify_lifecycle(product, resolve)
}

pub fn validate_native_recovery_phase(
    invocation: &Value,
    capture: &Value,
    stdout: &[u8],
    cli: &Value,
    provider: &Value,
    current_output: &str,
) -> VerificationResult<()> {
    fields(
        capture,
        &[
            "output_directory",
            "artifacts",
            "native_status",
            "deadline_exhausted",
            "recovery",
            "native_quiescence",
        ],
        &[],
    )?;
    if capture["native_status"] != 0
        || capture["deadline_exhausted"] != false
        || capture["recovery"] != json!({"Ok":null})
        || capture["native_quiescence"] != json!({"Ok":null})
        || capture["artifacts"]
            .as_array()
            .is_none_or(|rows| rows.is_empty() || rows.len() > 64)
    {
        return Err("installed recovery lacks actual successful native wait and quiescence".into());
    }
    header(
        invocation,
        "memcordon.windows-native-recovery-invocation",
        1,
    )?;
    fields(
        invocation,
        &[
            "format",
            "revision",
            "cli",
            "provider",
            "cwd",
            "argv_utf16",
            "environment_cleared",
            "command_budget_millis",
        ],
        &[],
    )?;
    let directory = format!(
        "{}\\outer-finalization",
        current_output.trim_end_matches(['\\', '/'])
    );
    let cwd = invocation["cwd"]
        .as_str()
        .ok_or("native recovery actual cwd absent")?;
    let captured = capture["output_directory"]
        .as_str()
        .ok_or("native recovery actual capture directory absent")?;
    let argv: Vec<Vec<u16>> = serde_json::from_value(invocation["argv_utf16"].clone())
        .map_err(|error| error.to_string())?;
    let budget = invocation["command_budget_millis"]
        .as_u64()
        .filter(|value| (100..=60000).contains(value))
        .ok_or("native recovery command budget exceeds original bounded operation")?;
    if invocation["cli"] != *cli
        || invocation["provider"] != *provider
        || invocation["environment_cleared"] != true
        || cwd.replace('/', "\\") != directory.replace('/', "\\")
        || captured.replace('/', "\\") != directory.replace('/', "\\")
        || argv.len() != 3
        || argv[0] != "windows-recover".encode_utf16().collect::<Vec<_>>()
        || argv[1] != "converge".encode_utf16().collect::<Vec<_>>()
    {
        return Err("installed recovery substitutes actual selected CLI/provider/argv/cwd".into());
    }
    let duration = String::from_utf16(&argv[2]).map_err(|error| error.to_string())?;
    if duration.is_empty() || !duration.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("native recovery duration is not exact finite decimal argv".into());
    }
    let duration = duration.parse::<u64>().map_err(|error| error.to_string())?;
    if duration == 0 || duration > 30000 || duration > budget.saturating_sub(100) {
        return Err("native recovery renews or exceeds its original command budget".into());
    }
    let inventory = crate::validate_json_document(stdout)?;
    fields(
        &inventory,
        &[
            "schema_version",
            "challenge",
            "provider_generation",
            "current_boot_identity",
            "executing",
            "incomplete_proof",
            "unacknowledged_outboxes",
            "ack_retirement_in_progress",
            "completed_tombstones",
            "active_admissions",
            "quarantined",
        ],
        &[],
    )?;
    if inventory["schema_version"] != 1
        || inventory["provider_generation"] != provider["generation"]
        || inventory["challenge"].as_str().is_none_or(str::is_empty)
        || inventory["current_boot_identity"]
            .as_str()
            .is_none_or(str::is_empty)
        || inventory["completed_tombstones"]
            .as_u64()
            .is_none_or(|count| u32::try_from(count).is_err())
        || [
            "executing",
            "incomplete_proof",
            "unacknowledged_outboxes",
            "ack_retirement_in_progress",
            "active_admissions",
            "quarantined",
        ]
        .iter()
        .any(|field| inventory[field] != 0)
    {
        return Err("actual native provider recovery inventory remains unresolved or belongs to another generation".into());
    }
    Ok(())
}

pub fn validate_package_command(
    invocation: &Value,
    capture: &Value,
    operation: &str,
    program: &str,
    directory: &str,
    image_sha256: &str,
) -> VerificationResult<()> {
    validate_package_command_status(
        invocation,
        capture,
        operation,
        program,
        directory,
        image_sha256,
        0,
    )
}

pub fn validate_failed_package_command(
    invocation: &Value,
    capture: &Value,
    operation: &str,
    program: &str,
    directory: &str,
    image_sha256: &str,
) -> VerificationResult<()> {
    validate_package_command_status(
        invocation,
        capture,
        operation,
        program,
        directory,
        image_sha256,
        125,
    )
}

fn validate_package_command_status(
    invocation: &Value,
    capture: &Value,
    operation: &str,
    program: &str,
    directory: &str,
    image_sha256: &str,
    status: i64,
) -> VerificationResult<()> {
    if !["install", "verify", "upgrade", "uninstall"].contains(&operation) {
        return Err("unknown actual package operation".into());
    }
    header(capture, "memcordon.package-operation-capture", 1)?;
    fields(
        capture,
        &[
            "format",
            "revision",
            "operation",
            "operation_complete",
            "streams_available",
            "stdout_reader_finished",
            "stderr_reader_finished",
            "observed_exit_code",
            "failure",
        ],
        &[],
    )?;
    if capture["operation"] != operation
        || capture["operation_complete"] != true
        || capture["streams_available"] != true
        || capture["stdout_reader_finished"] != true
        || capture["stderr_reader_finished"] != true
        || capture["observed_exit_code"] != status
        || if status == 0 {
            !capture["failure"].is_null()
        } else {
            capture["failure"].as_str().is_none_or(str::is_empty)
        }
    {
        return Err(
            "package command lacks actual successful native wait and complete streams".into(),
        );
    }
    header(invocation, "memcordon.windows-package-invocation", 1)?;
    fields(
        invocation,
        &[
            "format",
            "revision",
            "operation",
            "program_utf16",
            "argv_utf16",
            "cwd_utf16",
            "image_sha256",
            "budget_millis",
        ],
        &[],
    )?;
    crate::digest(image_sha256)?;
    let cwd: Vec<u16> = serde_json::from_value(invocation["cwd_utf16"].clone())
        .map_err(|error| error.to_string())?;
    let cwd = String::from_utf16(&cwd).map_err(|error| error.to_string())?;
    if invocation["operation"] != operation
        || invocation["argv_utf16"]
            != json!([
                "package".encode_utf16().collect::<Vec<_>>(),
                operation.encode_utf16().collect::<Vec<_>>()
            ])
        || invocation["program_utf16"] != json!(program.encode_utf16().collect::<Vec<_>>())
        || invocation["image_sha256"] != image_sha256
        || cwd.replace('/', "\\") != directory.replace('/', "\\")
        || invocation["budget_millis"]
            .as_u64()
            .is_none_or(|value| value == 0 || value > 120_000)
    {
        return Err(
            "package raw command differs from actual selected binary/argv/cwd/bounded budget"
                .into(),
        );
    }
    Ok(())
}

fn capacity(
    evidence: &CaseEvidenceV2,
    product: &ProductObservationV2,
    resolve: Resolver<'_>,
) -> VerificationResult<()> {
    let selected = provider(product, resolve)?;
    let semantic: crate::SemanticObservation =
        crate::wire::decode(&resolve(&evidence.semantic_observation)?)?;
    let vector = semantic
        .windows_capacity
        .as_ref()
        .ok_or("current capacity vector absent")?;
    crate::validate_windows_capacity_shape(vector, &evidence.key)?;
    let generation = selected["generation"]
        .as_str()
        .ok_or("actual capacity provider generation absent")?;
    let mut boot = None;
    for path in &vector.inventories {
        let raw = document(path, resolve)?;
        crate::validate_windows_capacity_inventory(&raw, generation)?;
        let current = raw["current_boot_identity"]
            .as_str()
            .ok_or("native capacity boot absent")?
            .to_owned();
        if boot.as_ref().is_some_and(|prior| prior != &current) {
            return Err("capacity native boot changed between original attempts".into());
        }
        boot = Some(current);
    }
    let mut challenges = BTreeSet::new();
    let mut attempts = BTreeSet::new();
    let mut roots = BTreeSet::new();
    let mut first: Option<(
        CaseEvidenceV2,
        crate::NativeObservation,
        crate::SemanticObservation,
    )> = None;
    for (ordinal, path) in vector.attempts.iter().enumerate() {
        let child: CaseEvidenceV2 = crate::wire::decode(&resolve(path)?)?;
        if child.format != "memcordon.consumer-readiness.case"
            || child.revision != 2
            || child.key != evidence.key
            || child.run_id != evidence.run_id
            || child.source_commit != evidence.source_commit
            || child.source_tree_sha256 != evidence.source_tree_sha256
            || child.lease_id != evidence.lease_id
            || child.fixture_sha256 != evidence.fixture_sha256
            || child.fixture_source_sha256 != evidence.fixture_source_sha256
            || child.component_recipe_id.is_some()
            || crate::sha256(&resolve(&child.fixture)?) != child.fixture_sha256
            || crate::sha256(&resolve(&child.fixture_source)?) != child.fixture_source_sha256
            || crate::sha256(&resolve(&child.input)?) != child.input_sha256
        {
            return Err(
                "current capacity constituent substitutes source/fixture/lease/custody".into(),
            );
        }
        let child_semantic: crate::SemanticObservation =
            crate::wire::decode(&resolve(&child.semantic_observation)?)?;
        if child_semantic.windows_capacity.is_some()
            || child_semantic.key != evidence.key
            || child_semantic.run_id != evidence.run_id
        {
            return Err(
                "current capacity constituent recurses or changes original semantic key".into(),
            );
        }
        let challenge = resolve(&child_semantic.challenge)?;
        let input = document(&child.input, resolve)?;
        if challenge.len() != 32
            || challenge.iter().all(|byte| *byte == 0)
            || !challenges.insert(crate::sha256(&challenge))
            || input["challenge_sha256"] != crate::sha256(&challenge)
            || input["run_id"] != evidence.run_id
            || input["key"]
                != serde_json::to_value(&evidence.key).map_err(|error| error.to_string())?
        {
            return Err(
                "current capacity constituent lacks distinct original native challenge/input"
                    .into(),
            );
        }
        let native: crate::NativeObservation =
            crate::wire::decode(&resolve(&child.native_observation)?)?;
        let root = (
            native.root_pid.ok_or("capacity actual root absent")?,
            native.root_birth.ok_or("capacity root birth absent")?,
        );
        if native.run_id != evidence.run_id
            || native.target != evidence.key.target
            || native.lease_id != evidence.lease_id
            || native.origin != crate::OutcomeOrigin::Target
            || native.provider_generation.as_deref() != Some(generation)
            || native.runtime_manifest_sha256.as_deref()
                != selected["runtime_manifest_sha256"].as_str()
            || !attempts.insert(
                native
                    .attempt_id
                    .clone()
                    .ok_or("capacity original attempt absent")?,
            )
            || !roots.insert(root)
        {
            return Err(
                "current capacity reuses or substitutes held native attempt/root/provider".into(),
            );
        }
        let overlap = if evidence.key.scenario == "bounded-concurrency" && ordinal == 1 {
            let (_, first_native, first_semantic) = first
                .as_ref()
                .ok_or("current capacity original first attempt absent")?;
            let behavior = first_semantic
                .fixture_behavior
                .as_ref()
                .ok_or("first actual Joint behavior absent")?;
            let peer = |role: &str| -> VerificationResult<&str> {
                behavior
                    .peer_artifacts
                    .iter()
                    .find(|artifact| artifact.role == role)
                    .map(|artifact| artifact.path.as_str())
                    .ok_or("first capacity native peer reference absent".into())
            };
            let first_live = document(peer("native-live-association")?, resolve)?;
            let live = document(
                vector
                    .overlap_live_association
                    .as_deref()
                    .ok_or("actual overlap live observation absent")?,
                resolve,
            )?;
            let guardian = document(
                vector
                    .overlap_held_guardian
                    .as_deref()
                    .ok_or("actual overlap held guardian absent")?,
                resolve,
            )?;
            header(&live, "memcordon.windows-live-guardian-observation", 1)?;
            fields(
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
            for field in [
                "association",
                "live_nonce",
                "live_target_identity",
                "guardian_identity",
            ] {
                if live[field] != first_live[field] {
                    return Err("overlap changed the actual first held native association".into());
                }
            }
            if guardian != live["guardian_identity"] {
                return Err("overlap did not independently hold actual first guardian".into());
            }
            fields(&guardian, &["process_id", "creation_time_100ns"], &[])?;
            if guardian["process_id"]
                .as_u64()
                .is_none_or(|pid| pid == 0 || pid > u32::MAX as u64)
                || guardian["creation_time_100ns"]
                    .as_u64()
                    .is_none_or(|birth| birth == 0)
            {
                return Err("overlap held guardian native identity absent".into());
            }
            let peer = document(peer("native-tcp-peer")?, resolve)?;
            let root = (
                first_native
                    .root_pid
                    .ok_or("original first held root absent")?,
                first_native
                    .root_birth
                    .ok_or("original first root birth absent")?,
            );
            let peer_identity = (
                u32::try_from(peer["pid"].as_u64().ok_or("actual first peer pid absent")?)
                    .map_err(|error| error.to_string())?,
                peer["birth"]
                    .as_u64()
                    .ok_or("actual first peer birth absent")?,
            );
            if peer_identity == root
                || peer["parent_pid"] != root.0
                || peer["parent_birth"] != root.1
                || peer["native_parent_edge_observed"] != true
                || peer["parent_and_child_held_live"] != true
            {
                return Err("overlap exclusion changes actual held first parent/child edge".into());
            }
            Some(crate::behavior::CapacityOverlap {
                live,
                excluded: [root, peer_identity],
            })
        } else {
            None
        };
        positive_scope(&child, &input, product, resolve, overlap.as_ref())?;
        if ordinal == 0 {
            let mut representative = child.clone();
            representative.semantic_observation = evidence.semantic_observation.clone();
            if serde_json::to_value(&representative).map_err(|error| error.to_string())?
                != serde_json::to_value(evidence).map_err(|error| error.to_string())?
            {
                return Err(
                    "current capacity representative changes actual first raw constituent".into(),
                );
            }
            first = Some((child, native, child_semantic));
        }
    }
    let (_, native, mut expected) = first.ok_or("actual capacity first constituent absent")?;
    expected.windows_capacity = Some(vector.clone());
    for operation in [
        format!("capacity-{}", evidence.key.scenario),
        "fresh-admission".into(),
        "capacity-attempts".into(),
    ] {
        expected.operations.push(crate::OperationObservation {
            operation,
            attempt_id: native.attempt_id.clone(),
            root_pid: native.root_pid,
            observer: "owned-native-capacity".into(),
            native_receipt: vector
                .inventories
                .last()
                .ok_or("capacity final inventory absent")?
                .clone(),
        });
    }
    expected.counters.insert(
        "capacity-attempts".into(),
        u64::try_from(vector.attempts.len()).map_err(|error| error.to_string())?,
    );
    if serde_json::to_value(&expected).map_err(|error| error.to_string())?
        != serde_json::to_value(&semantic).map_err(|error| error.to_string())?
    {
        return Err(
            "current capacity outer counters/operations do not describe exact native vector".into(),
        );
    }
    Ok(())
}

fn component(
    evidence: &CaseEvidenceV2,
    input: &Value,
    build: &ComponentBuild,
    semantic: &crate::SemanticObservation,
    resolve: Resolver<'_>,
) -> VerificationResult<()> {
    let test = semantic
        .component_test
        .as_ref()
        .ok_or("current component test absent")?;
    if evidence.lease_id.is_some()
        || evidence.request.is_some()
        || evidence.raw_result.is_some()
        || evidence.authenticated_terminal.is_some()
        || evidence.recovery.is_some()
        || !build.instrumented
        || evidence.component_recipe_id.as_deref() != Some(build.recipe_id.as_str())
        || test.recipe_id != build.recipe_id
        || test.native_exit != 0
        || test.tests_executed != 1
        || test.tests_failed != 0
        || test.tests_ignored != 0
        || semantic.component_actors.is_some()
        || semantic.windows_capacity.is_some()
        || semantic.fixture_behavior.is_some()
        || semantic.negative_probe.is_some()
        || !semantic.operations.is_empty()
        || !semantic.comparisons.is_empty()
        || !semantic.counters.is_empty()
    {
        return Err(
            "current native component substitutes installed authority or another test/recipe"
                .into(),
        );
    }
    let receipt_bytes = resolve(&test.native_receipt)?;
    let receipt: super::windows_component::WindowsNativeComponentReceiptV2 =
        crate::wire::decode(&receipt_bytes)?;
    if receipt.format != "memcordon.windows-native-component"
        || receipt.revision != 2
        || receipt.run_id != evidence.run_id
        || receipt.recipe_id != build.recipe_id
        || receipt.test_name != test.test_name
        || receipt.native_target != evidence.key.target
    {
        return Err("current native component receipt source/test/target differs".into());
    }
    let native: crate::NativeObservation =
        crate::wire::decode(&resolve(&evidence.native_observation)?)?;
    if receipt.payload["kind"] == "binding"
        && (receipt.payload["caller_identity"]["process_id"].as_u64()
            != native.root_pid.map(u64::from)
            || receipt.payload["caller_identity"]["creation_time_100ns"].as_u64()
                != native.root_birth)
    {
        return Err("retained binding caller differs from actual held native test process".into());
    }
    let retirement: crate::RetirementObservation =
        crate::wire::decode(&resolve(&evidence.retirement)?)?;
    let invocation: crate::NativeInvocation = crate::wire::decode(&resolve(&evidence.invocation)?)?;
    let executable = if receipt.test_name.starts_with("windows_parser::") {
        build
            .parser_executable
            .as_deref()
            .ok_or("current parser executable absent")?
    } else {
        &build.executable
    };
    let hash = crate::sha256(&resolve(executable)?);
    if receipt.executable_sha256 != hash
        || native.executable_sha256 != hash
        || invocation.executable_sha256 != hash
        || native.invocation_sha256 != invocation.association_sha256
        || native.origin != crate::OutcomeOrigin::ComponentRegression
        || native.frontend_status != 0
        || native.attempt_id.is_some()
        || native.target_status.is_some()
        || native.held_processes.len() != 1
        || !retirement.target_reaped_or_absent
        || !retirement.aggregate_empty
        || !retirement.independently_observed
        || retirement.guardian_retired
        || retirement.native_handles_closed
        || retirement.final_job_handles_closed.is_some()
        || !retirement.outstanding.is_empty()
        || !retirement.failed_operations.is_empty()
    {
        return Err(
            "current component invents target Job retirement or changes measured executable".into(),
        );
    }
    let unique = |name: &str| -> VerificationResult<&str> {
        let paths = evidence
            .outputs
            .iter()
            .filter(|path| path.rsplit('/').next() == Some(name))
            .collect::<Vec<_>>();
        if paths.len() != 1 {
            return Err(format!("current native test needs one actual {name}"));
        }
        Ok(paths[0].as_str())
    };
    let launch = document(unique("native-invocation.json")?, resolve)?;
    let exit = document(unique("native-exit.json")?, resolve)?;
    let retired = document(unique("native-retirement.json")?, resolve)?;
    header(&launch, "memcordon.windows-native-test-invocation", 1)?;
    header(&exit, "memcordon.windows-native-test-exit", 1)?;
    header(&retired, "memcordon.windows-native-test-retirement", 1)?;
    for observed in [&launch, &exit] {
        if observed["run_id"] != evidence.run_id
            || observed["recipe_id"] != build.recipe_id
            || observed["native_target"] != evidence.key.target
            || observed["executable_sha256"] != hash
        {
            return Err("current native test raw process source/image differs".into());
        }
    }
    if exit["native_status"] != 0
        || exit["capture_complete"] != true
        || exit["input_delivered"] != true
        || launch["environment_cleared"] != true
        || retired["process_id"].as_u64() != native.root_pid.map(u64::from)
        || retired["creation_time_100ns"].as_u64() != native.root_birth
        || retired["image_sha256"] != hash
        || retired["held_before_input_delivery"] != true
        || retired["retirement_observed"] != true
        || retired["same_image_helpers_absent"] != true
    {
        return Err("current native test lacks actual held process execution/retirement".into());
    }
    let mut arguments = vec![launch["program_utf16"].clone()];
    arguments.extend(
        launch["argv_utf16"]
            .as_array()
            .ok_or("actual native test argv absent")?
            .iter()
            .cloned(),
    );
    if serde_json::to_value(&invocation.arguments).map_err(|error| error.to_string())?
        != serde_json::json!({"encoding":"windows_utf16","values":arguments})
    {
        return Err("current native test invocation differs from actual UTF16 command".into());
    }
    if input["run_id"] != evidence.run_id
        || input["key"] != serde_json::to_value(&evidence.key).map_err(|error| error.to_string())?
        || input["deadline_millis"] != Value::Null
        || input["memory_bytes"] != Value::Null
    {
        return Err("current component input substitutes installed resources".into());
    }
    let captured = resolve(&test.raw_test_output)?;
    if test.raw_test_output != evidence.stdout {
        return Err("native test stdout crosswalk differs".into());
    }
    let captured = std::str::from_utf8(&captured).map_err(|error| error.to_string())?;
    let line = format!("test {} ... ok", test.test_name);
    if captured
        .lines()
        .filter(|value| *value == "running 1 test")
        .count()
        != 1
        || captured.lines().filter(|value| *value == line).count() != 1
        || captured
            .lines()
            .filter(|value| {
                value.starts_with("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; ")
            })
            .count()
            != 1
    {
        return Err("current native harness did not execute exactly selected real test".into());
    }
    let mut paths = BTreeSet::new();
    component_paths(
        &serde_json::to_value(&receipt.payload).map_err(|error| error.to_string())?,
        &mut paths,
    );
    let mut values = BTreeMap::new();
    let mut total = 0usize;
    for path in paths {
        crate::custody::validate_path(&path)?;
        let bytes = resolve(&path)?;
        total = total
            .checked_add(bytes.len())
            .ok_or("current component bytes overflow")?;
        if total as u64 > crate::MAX_PRODUCER_BYTES || values.len() >= crate::MAX_PRODUCER_ARTIFACTS
        {
            return Err("current component byte custody exceeds bound".into());
        }
        values.insert(path, bytes);
    }
    super::windows_component::validate_windows_component(
        &receipt,
        &evidence.key,
        &crate::custody::Custody::from_verified_values(values)?,
    )
}

fn component_paths(value: &Value, paths: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                if [
                    "before_journal",
                    "after_journal",
                    "record",
                    "after_record",
                    "first_response",
                    "repeated_response",
                    "ack_record",
                    "staged_ack",
                    "completed_ack",
                    "retired_response",
                    "repeated_retired_response",
                    "available_journal",
                    "expired_journal",
                    "expiry_record",
                    "before_record",
                    "replacement_observation",
                    "after_refusal_record",
                    "after_matching_record",
                    "mismatched_receipt",
                    "matching_receipt",
                    "response",
                    "original",
                    "projection",
                    "caller_envelope",
                    "authority",
                    "replayed_response",
                    "before_reservation",
                    "after_refusal_reservation",
                    "retirement_without_local_proof",
                    "published_record",
                ]
                .contains(&key.as_str())
                    && let Some(path) = value.as_str()
                {
                    paths.insert(path.into());
                }
                component_paths(value, paths);
            }
        }
        Value::Array(values) => {
            for value in values {
                component_paths(value, paths);
            }
        }
        _ => {}
    }
}

fn loss(
    evidence: &CaseEvidenceV2,
    product: &ProductObservationV2,
    resolve: Resolver<'_>,
) -> VerificationResult<()> {
    let selected = provider(product, resolve)?;
    let unique = |name: &str| -> VerificationResult<&str> {
        let paths = evidence
            .outputs
            .iter()
            .filter(|path| path.rsplit('/').next() == Some(name))
            .collect::<Vec<_>>();
        if paths.len() != 1 {
            return Err(format!("current loss requires one actual {name}"));
        }
        Ok(paths[0].as_str())
    };
    let observation = document(unique("loss-observation.json")?, resolve)?;
    header(&observation, "memcordon.windows-loss-observation", 2)?;
    fields(
        &observation,
        &["format", "revision", "run_id", "key", "provider", "loss"],
        &[],
    )?;
    if observation["run_id"] != evidence.run_id
        || observation["key"]
            != serde_json::to_value(&evidence.key).map_err(|error| error.to_string())?
        || observation["provider"] != selected
    {
        return Err("current loss envelope crosses original selected case/provider".into());
    }
    let loss: crate::WindowsLossEvidence =
        serde_json::from_value(observation["loss"].clone()).map_err(|error| error.to_string())?;
    if evidence.attempt_observation.as_ref() != Some(&loss.live_observation)
        || evidence.recovery.as_ref() != Some(&loss.recovery)
        || evidence.raw_result != loss.original_result
        || evidence.stdout != loss.stdout
        || evidence.stderr != loss.stderr
    {
        return Err("current loss crosswalk substitutes original captured artifacts".into());
    }
    let native: crate::NativeObservation =
        crate::wire::decode(&resolve(&evidence.native_observation)?)?;
    let invocation: crate::NativeInvocation = crate::wire::decode(&resolve(&evidence.invocation)?)?;
    let semantic: crate::SemanticObservation =
        crate::wire::decode(&resolve(&evidence.semantic_observation)?)?;
    let exit = document(unique("native-exit.json")?, resolve)?;
    if exit["native_status"] != native.frontend_status
        || exit["capture_complete"] != true
        || exit["executable_sha256"] != invocation.executable_sha256
    {
        return Err("current loss frontend status/capture differs from actual native wait".into());
    }
    let mut paths = BTreeSet::from([
        evidence.invocation.clone(),
        invocation.environment.clone(),
        evidence.semantic_observation.clone(),
        semantic.challenge.clone(),
        evidence
            .request
            .clone()
            .ok_or("current loss original workload request absent")?,
        unique("provider-request.bin")?.into(),
    ]);
    for value in observation["loss"]
        .as_object()
        .ok_or("loss references absent")?
        .values()
    {
        if let Some(path) = value.as_str() {
            paths.insert(path.into());
        }
    }
    let mut values = BTreeMap::new();
    let mut total = 0usize;
    for path in paths {
        crate::custody::validate_path(&path)?;
        let bytes = resolve(&path)?;
        total = total
            .checked_add(bytes.len())
            .ok_or("loss byte custody overflow")?;
        if total as u64 > crate::MAX_PRODUCER_BYTES || values.len() >= crate::MAX_PRODUCER_ARTIFACTS
        {
            return Err("loss byte custody exceeds bound".into());
        }
        values.insert(path, bytes);
    }
    let custody = crate::custody::Custody::from_verified_values(values)?;
    super::windows_loss::validate_windows_loss(
        evidence,
        &loss,
        unique("provider-request.bin")?,
        &native,
        &evidence.key,
        product,
        &custody,
    )
}

fn refusal(
    evidence: &CaseEvidenceV2,
    product: &ProductObservationV2,
    semantic: &Value,
    resolve: Resolver<'_>,
) -> VerificationResult<()> {
    header(semantic, "memcordon.windows-refusal-observation", 2)?;
    if semantic["scenario"] != evidence.key.scenario
        || evidence.raw_result.is_some()
        || evidence.authenticated_terminal.is_some()
        || evidence.recovery.is_some()
    {
        return Err("current refusal fabricates target execution evidence".into());
    }
    let expected = provider(product, resolve)?;
    if semantic["provider"] != expected {
        return Err("current refusal selected provider differs".into());
    }
    let agent = product
        .components
        .iter()
        .find(|component| component.role == "sealed-agent")
        .ok_or("current Windows agent absent")?;
    guardian(
        &document(&evidence.native_observation, resolve)?,
        &expected,
        &agent.installed_sha256,
    )?;
    let retirement = document(&evidence.retirement, resolve)?;
    header(
        &retirement,
        "memcordon.windows-native-refusal-quiescence",
        2,
    )?;
    if retirement["provider"] != expected {
        return Err("current refusal retirement differs".into());
    }
    yes(
        &retirement,
        &["guardian_native_quiescence", "fixture_processes_absent"],
    )?;
    let raw = semantic["raw_prefix"]
        .as_str()
        .ok_or("actual refusal capture prefix absent")?;
    let read = |name: &str| document(&format!("{raw}/{name}"), resolve);
    if evidence.key.scenario == "component-substitution" {
        let original = read("original-acquisition.json")?;
        let changed = read("substituted-acquisition.json")?;
        let observed = read("acquisition-refusal.json")?;
        if original["provider"] != expected
            || changed["installed_agent"] != original["fixture"]
            || changed["installed_agent"] == original["installed_agent"]
            || observed["changed_component"] != "installed-agent"
            || observed["installation_mutated"] != false
            || observed["target_released"] != false
            || observed["refusal"].as_str().is_none_or(str::is_empty)
        {
            return Err(
                "current component substitution did not reach actual selected-byte refusal".into(),
            );
        }
        return Ok(());
    }
    let exit = read("native-exit.json")?;
    if exit["capture_complete"] != true {
        return Err("current refusal native frontend capture is incomplete".into());
    }
    if evidence.key.scenario == "argv-nul-rejection" {
        let observation = read("native-argument-observation.json")?;
        if observation["code"] != "MCSEALED-WINDOWS-REQUEST"
            || observation["category"] != "Usage"
            || observation["argument_utf16"] != json!([97, 0, 98])
            || observation["target_released"] != false
            || !observation["target_pid"].is_null()
        {
            return Err("actual current NUL refusal differs".into());
        }
        return Ok(());
    }
    let allowed = [
        ("C-ADMISSION", "unsupported-profile"),
        ("C-ADMISSION", "malformed-request"),
        ("C-ADMISSION", "unsupported-format"),
        ("C-ADMISSION", "identity-override-rejected"),
        ("W-BINDING", "request-token-override-rejected"),
        ("W-BINDING", "unsupported-public-request"),
        ("W-STATUS", "admission-refusal"),
    ];
    if !allowed.contains(&(evidence.key.family.as_str(), evidence.key.scenario.as_str())) {
        return Err("undeclared current refusal case".into());
    }
    let observed = read("request-refusal.json")?;
    header(&observed, "memcordon.windows-request-refusal", 2)?;
    yes(&observed, &["target_transcript_absent", "report_absent"])?;
    if observed["native_status"] != 2 || observed["scenario"] != evidence.key.scenario {
        return Err("actual current request refusal status differs".into());
    }
    let stderr = resolve(&evidence.stderr)?;
    let detail = std::str::from_utf8(&stderr).map_err(|error| error.to_string())?;
    let expected = match evidence.key.scenario.as_str() {
        "unsupported-public-request" => "MCUSAGE-WORKLOAD-BOUNDARY",
        _ => "MCUSAGE-WORKLOAD-REQUEST",
    };
    if !detail.contains(expected) || observed["expected_diagnostic"] != expected {
        return Err("actual current refusal causal code differs".into());
    }
    Ok(())
}
