//! Fixture effects are behavioral data, never containment or authorization.
use crate::*;
use serde_json::Value;

fn validate_gate_diagnostic(value: &Value, name: &str, challenge: &[u8]) -> VerificationResult<()> {
    fn shape(value: &Value, required: &[&str], optional: &[&str]) -> VerificationResult<()> {
        let fields = value
            .as_object()
            .ok_or("gate diagnostic is not an object")?;
        if required.iter().any(|field| !fields.contains_key(*field))
            || fields.keys().any(|field| {
                !required.contains(&field.as_str()) && !optional.contains(&field.as_str())
            })
        {
            return Err("gate diagnostic missing/unknown fields".into());
        }
        Ok(())
    }
    shape(
        value,
        &[
            "revision",
            "descriptor",
            "descriptor_sha256",
            "name_utf16_sha256",
            "challenge_sha256",
            "work_cutoff_qpc",
            "qpc_frequency",
        ],
        &["namespace"],
    )?;
    let descriptor: Vec<u8> =
        serde_json::from_value(value["descriptor"].clone()).map_err(|error| error.to_string())?;
    let units = name.encode_utf16().collect::<Vec<_>>();
    let name_bytes = units
        .iter()
        .flat_map(|unit| unit.to_le_bytes())
        .collect::<Vec<_>>();
    if value["revision"] != 1
        || descriptor.len() < std::mem::size_of::<[u32; 5]>()
        || descriptor.len() > 64 * 1024
        || descriptor[0] != 1
        || u16::from_le_bytes(
            descriptor[2..4]
                .try_into()
                .map_err(|_| "gate security descriptor control width")?,
        ) & 0x8004
            != 0x8004
        || units.is_empty()
        || units.contains(&0)
        || value["descriptor_sha256"] != sha256(&descriptor)
        || value["name_utf16_sha256"] != sha256(&name_bytes)
        || value["challenge_sha256"] != sha256(challenge)
        || value["work_cutoff_qpc"]
            .as_u64()
            .is_none_or(|cutoff| cutoff == 0)
        || value["qpc_frequency"]
            .as_u64()
            .is_none_or(|frequency| frequency == 0)
    {
        return Err(
            "gate diagnostic bytes, name/challenge or original native cutoff differ".into(),
        );
    }
    if let Some(proof) = value.get("namespace").filter(|proof| !proof.is_null()) {
        shape(
            proof,
            &[
                "revision",
                "components",
                "path_sha256",
                "challenge_sha256",
                "name_utf16_sha256",
                "descriptor_sha256",
                "work_cutoff_qpc",
                "qpc_frequency",
                "controller_same_original",
                "controller_absolute_same_original",
                "complete",
            ],
            &[],
        )?;
        let components: Vec<Vec<u16>> = serde_json::from_value(proof["components"].clone())
            .map_err(|error| error.to_string())?;
        if components.is_empty() || components.len() > 17 {
            return Err("gate namespace diagnostic component bound differs".into());
        }
        let mut path = Vec::<u16>::new();
        for component in &components {
            if component.is_empty()
                || component
                    .iter()
                    .any(|unit| [0, u16::from(b'/'), u16::from(b'\\')].contains(unit))
                || component.iter().copied().eq(".".encode_utf16())
                || component.iter().copied().eq("..".encode_utf16())
            {
                return Err("gate namespace diagnostic has an escaping native component".into());
            }
            path.push(u16::from(b'\\'));
            path.extend_from_slice(component);
            if path
                .len()
                .checked_add(1)
                .and_then(|length| length.checked_mul(std::mem::size_of::<u16>()))
                .is_none_or(|bytes| bytes > 32 * 1024)
            {
                return Err("gate namespace diagnostic path exceeds native bound".into());
            }
        }
        let path_bytes = path
            .iter()
            .flat_map(|unit| unit.to_le_bytes())
            .collect::<Vec<_>>();
        let local = "Local\\".encode_utf16().collect::<Vec<_>>();
        if proof["revision"] != 1
            || proof["path_sha256"] != sha256(&path_bytes)
            || proof["controller_same_original"] != true
            || proof["controller_absolute_same_original"] != true
            || proof["complete"] != true
            || units.strip_prefix(local.as_slice()) != components.last().map(Vec::as_slice)
        {
            return Err("gate namespace diagnostic does not bind the same original event".into());
        }
        for field in [
            "challenge_sha256",
            "name_utf16_sha256",
            "descriptor_sha256",
            "work_cutoff_qpc",
            "qpc_frequency",
        ] {
            if proof[field] != value[field] {
                return Err("gate namespace diagnostic crosses original snapshot binding".into());
            }
        }
    }
    Ok(())
}

pub(crate) struct Facts {
    pub operations: BTreeSet<String>,
    pub counters: BTreeMap<String, u64>,
}
pub(crate) struct CapacityOverlap {
    pub live: Value,
    pub excluded: [(u32, u64); 2],
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Event {
    sequence: u32,
    stage: String,
    pid: u32,
    ordinal: Option<u32>,
    value: Vec<u8>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NativeBarrier {
    format: String,
    revision: u32,
    stage: String,
    ordinal: u32,
    root_pid: u32,
    live_children: u64,
    members: Vec<BarrierMember>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BarrierMember {
    pid: u32,
    birth: u64,
    parent_pid: Option<u32>,
    parent_birth: Option<u64>,
    held_live_before_release: bool,
}

pub(crate) fn validate(
    behavior: &FixtureBehavior,
    semantic: &SemanticObservation,
    native: &NativeObservation,
    input: &FixtureInput,
    custody: &custody::Custody,
) -> VerificationResult<Facts> {
    validate_in_scope(behavior, semantic, native, input, custody, None)
}
pub(crate) fn validate_capacity_overlap(
    behavior: &FixtureBehavior,
    semantic: &SemanticObservation,
    native: &NativeObservation,
    input: &FixtureInput,
    custody: &custody::Custody,
    overlap: &CapacityOverlap,
) -> VerificationResult<Facts> {
    if semantic.key.family != "W-CAPACITY"
        || semantic.key.scenario != "bounded-concurrency"
        || !semantic.key.target.ends_with("windows-msvc")
    {
        return Err(
            "native overlap scope belongs only to the actual second capacity constituent".into(),
        );
    }
    validate_in_scope(behavior, semantic, native, input, custody, Some(overlap))
}
fn validate_in_scope(
    behavior: &FixtureBehavior,
    semantic: &SemanticObservation,
    native: &NativeObservation,
    input: &FixtureInput,
    custody: &custody::Custody,
    overlap: Option<&CapacityOverlap>,
) -> VerificationResult<Facts> {
    if behavior.peer_artifacts.len() > 256 {
        return Err("fixture peer artifact count exceeds bound".into());
    }
    let mut peers = BTreeMap::new();
    for artifact in &behavior.peer_artifacts {
        if peers
            .insert(artifact.role.as_str(), artifact.path.as_str())
            .is_some()
        {
            return Err("duplicate actual fixture peer product role".into());
        }
    }
    if !semantic.key.target.ends_with("windows-msvc") {
        return Err("Windows factual behavior decoder received another target".into());
    }
    let descriptor: Value = wire::decode(custody.bytes(&behavior.descriptor)?)?;
    let allowed = [
        "format",
        "revision",
        "case",
        "output_root",
        "transcript",
        "challenge",
        "stdout",
        "stderr",
        "arguments",
        "application_status",
        "churn_creations",
        "churn_live",
        "denied_write_paths",
        "sentinel_handles",
        "descendant_gate",
        "start_gate",
        "completion_gate",
        "cohort_gate",
        "generation_gate",
        "toolchain",
    ];
    let object = descriptor
        .as_object()
        .ok_or("Windows descriptor is not object")?;
    if object.len() != allowed.len() + usize::from(object.contains_key("gate_access_diagnostic"))
        || object
            .keys()
            .any(|key| !allowed.contains(&key.as_str()) && key != "gate_access_diagnostic")
        || descriptor["format"] != "memcordon.fixture-workload"
        || descriptor["revision"] != 1
    {
        return Err("raw Windows fixture descriptor differs from frozen schema".into());
    }
    let challenge: Vec<u8> =
        serde_json::from_value(descriptor["challenge"].clone()).map_err(|e| e.to_string())?;
    if challenge.is_empty()
        || challenge.len() > 4096
        || challenge != custody.bytes(&semantic.challenge)?
    {
        return Err("raw descriptor challenge differs from independent input".into());
    }
    if let Some(diagnostic) = object
        .get("gate_access_diagnostic")
        .filter(|value| !value.is_null())
    {
        validate_gate_diagnostic(
            diagnostic,
            descriptor["start_gate"]
                .as_str()
                .ok_or("diagnostic original gate name absent")?,
            &challenge,
        )?;
    }
    let events = events(custody.bytes(&behavior.transcript)?)?;
    let first = events.first().ok_or("fixture transcript empty")?;
    if first.stage != "started" || first.value != challenge || Some(first.pid) != native.root_pid {
        return Err(
            "fixture transcript root/start differs from authenticated native target".into(),
        );
    }
    let forced = matches!(
        native.origin,
        OutcomeOrigin::Deadline
            | OutcomeOrigin::Memory
            | OutcomeOrigin::Interrupted
            | OutcomeOrigin::ProviderFailure
    );
    if !forced
        && events
            .last()
            .is_none_or(|last| last.stage != "finished" || last.value != challenge)
    {
        return Err("fixture final event/challenge missing".into());
    }
    let token = events
        .iter()
        .find(|event| event.stage == "token-envelope")
        .ok_or("actual fixture token readback absent")?;
    let observed: Value = wire::decode(&token.value)?;
    let expected: Value = wire::decode(
        custody.bytes(
            behavior
                .expected_token
                .as_deref()
                .ok_or("independent caller token snapshot absent")?,
        )?,
    )?;
    for envelope in [&observed, &expected] {
        let fields = [
            "user_sid",
            "restricted",
            "integrity_rid",
            "elevated",
            "restricting_sids",
        ];
        if envelope.as_object().is_none_or(|value| {
            value.len() != fields.len()
                || value.keys().any(|field| !fields.contains(&field.as_str()))
        }) || ["restricted", "elevated"]
            .iter()
            .any(|field| envelope[*field].as_bool().is_none())
            || envelope["integrity_rid"]
                .as_u64()
                .is_none_or(|value| value > u32::MAX as u64)
        {
            return Err("original Windows token observation schema differs".into());
        }
        let user: Vec<u8> = serde_json::from_value(envelope["user_sid"].clone())
            .map_err(|error| error.to_string())?;
        let restricting: Vec<Vec<u8>> =
            serde_json::from_value(envelope["restricting_sids"].clone())
                .map_err(|error| error.to_string())?;
        let valid_sid = |sid: &[u8]| {
            sid.len() >= 8
                && sid[0] == 1
                && sid[1] <= 15
                && sid.len() == 8 + 4 * usize::from(sid[1])
        };
        if !valid_sid(&user)
            || restricting.len() > 4096
            || restricting.iter().any(|sid| !valid_sid(sid))
        {
            return Err("original Windows token native SID representation malformed".into());
        }
    }
    if observed != expected {
        return Err(
            "actual fixture token differs from independently captured caller envelope".into(),
        );
    }
    if events.iter().any(|event| {
        [
            "started",
            "finished",
            "token-envelope",
            "native-argv-observed",
            "sentinel-handles-excluded",
            "tcp-conflicting-bind",
            "tcp-listener-owned",
            "named-pipe-while-tcp-owned",
            "binary-files",
            "toolchain-compiled",
            "toolchain-test-child-dll-complete",
            "tcp-peer-complete",
        ]
        .contains(&event.stage.as_str())
            && Some(event.pid) != native.root_pid
    }) {
        return Err("Windows positive raw effect came from another native root".into());
    }
    let arguments: Vec<String> = serde_json::from_value(descriptor["arguments"].clone())
        .map_err(|error| error.to_string())?;
    let declared = NativeArguments::WindowsUtf16(
        arguments
            .iter()
            .map(|argument| argument.encode_utf16().collect())
            .collect(),
    );
    if serde_json::to_value(&declared).map_err(|error| error.to_string())?
        != serde_json::to_value(&input.target_argv).map_err(|error| error.to_string())?
    {
        return Err("descriptor tested argv suffix differs from independent vector".into());
    }
    let argv_event = events
        .iter()
        .find(|event| event.stage == "native-argv-observed")
        .ok_or("actual native argv event absent")?;
    let actual: NativeArguments = wire::decode(
        custody.bytes(
            peers
                .get("native-argv")
                .copied()
                .ok_or("actual native argv product absent")?,
        )?,
    )?;
    if serde_json::to_value(&actual).map_err(|error| error.to_string())?
        != serde_json::to_value(&declared).map_err(|error| error.to_string())?
        || wire::json(&argv_event.value)?
            != serde_json::to_value(&actual).map_err(|error| error.to_string())?
    {
        return Err("actual argv event/product differs from declared tested suffix".into());
    }
    let mut facts = Facts {
        operations: BTreeSet::new(),
        counters: BTreeMap::new(),
    };
    let retired: Value = wire::decode(
        custody.bytes(
            peers
                .get("native-retirement")
                .copied()
                .ok_or("raw independently held positive retirement absent")?,
        )?,
    )?;
    let mut fields = vec![
        "format",
        "revision",
        "association",
        "held_processes",
        "guardian_identity",
        "guardian_retirement_observed",
        "same_image_processes_absent",
        "global_quiescence_required",
    ];
    if overlap.is_some() {
        fields.extend(["excluded_live_association", "excluded_held_processes"]);
    }
    if retired.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
    }) || retired["format"]
        != (if overlap.is_some() {
            "memcordon.windows-native-overlap-retirement"
        } else {
            "memcordon.windows-native-positive-retirement"
        })
        || retired["revision"] != 1
        || retired["association"]["attempt_id"].as_str() != native.attempt_id.as_deref()
        || retired["association"]["request_sha256"].as_str() != native.request_sha256.as_deref()
        || retired["association"]["provider"]["generation"].as_str()
            != native.provider_generation.as_deref()
        || retired["association"]["provider"]["runtime_manifest_sha256"].as_str()
            != native.runtime_manifest_sha256.as_deref()
        || retired["guardian_retirement_observed"] != true
        || retired["same_image_processes_absent"] != overlap.is_none()
        || retired["global_quiescence_required"] != overlap.is_none()
    {
        return Err("raw positive native retirement/provider association differs".into());
    }
    if let Some(scope) = overlap {
        if retired["excluded_live_association"] != scope.live
            || retired["association"]["attempt_id"] == scope.live["association"]["attempt_id"]
        {
            return Err(
                "overlap retirement excludes another attempt or its own native authority".into(),
            );
        }
        crate::current::windows_facts::validate_windows_capacity_exclusions(
            &retired["excluded_held_processes"],
            &retired["excluded_live_association"],
            &scope.live,
            &scope.excluded,
            &native.held_processes,
        )?;
    }
    let mut identities = BTreeSet::new();
    for process in retired["held_processes"]
        .as_array()
        .ok_or("raw positive held identities absent")?
    {
        if process.as_object().is_none_or(|object| {
            object.len() != 5
                || object.keys().any(|key| {
                    ![
                        "pid",
                        "birth",
                        "parent_pid",
                        "parent_birth",
                        "retirement_observed",
                    ]
                    .contains(&key.as_str())
                })
        }) || process["retirement_observed"] != true
        {
            return Err("raw positive held retirement schema differs".into());
        }
        let identity = (
            process["pid"].as_u64().ok_or("retired PID absent")?,
            process["birth"].as_u64().ok_or("retired birth absent")?,
        );
        if !identities.insert(identity) {
            return Err("raw positive held identity duplicate".into());
        }
        let normalized = native
            .held_processes
            .iter()
            .find(|held| u64::from(held.pid) == identity.0 && held.birth == identity.1)
            .ok_or("raw positive held identity lacks normalized native association")?;
        if process["parent_pid"].as_u64() != normalized.parent_pid.map(u64::from)
            || process["parent_birth"].as_u64() != normalized.parent_birth
            || process["parent_pid"].is_null() != normalized.parent_pid.is_none()
            || process["parent_birth"].is_null() != normalized.parent_birth.is_none()
        {
            return Err("raw positive native parent identity differs".into());
        }
    }
    if identities
        != native
            .held_processes
            .iter()
            .map(|process| (u64::from(process.pid), process.birth))
            .collect()
        || native
            .held_processes
            .iter()
            .any(|process| !process.retirement_observed)
    {
        return Err("raw and normalized positive native held identities differ".into());
    }
    let live: Value = wire::decode(
        custody.bytes(
            peers
                .get("native-live-association")
                .copied()
                .ok_or("raw positive live guardian association absent")?,
        )?,
    )?;
    let mandatory = [
        "format",
        "revision",
        "challenge",
        "guardian_identity",
        "association",
    ];
    let optional = [
        "live_nonce",
        "live_target_identity",
        "worker_process_identity",
        "worker_thread_identity",
    ];
    if live.as_object().is_none_or(|object| {
        mandatory.iter().any(|key| !object.contains_key(*key))
            || object
                .keys()
                .any(|key| !mandatory.contains(&key.as_str()) && !optional.contains(&key.as_str()))
    }) || live["format"] != "memcordon.windows-live-guardian-observation"
        || live["revision"] != 1
        || live["association"] != retired["association"]
        || live["live_nonce"].as_str() != native.attempt_nonce.as_deref()
        || live["live_target_identity"]["process_id"].as_u64() != native.root_pid.map(u64::from)
        || live["live_target_identity"]["creation_time_100ns"].as_u64() != native.root_birth
        || live["guardian_identity"]["process_id"] != retired["guardian_identity"]["process_id"]
        || live["guardian_identity"]["creation_time_100ns"]
            != retired["guardian_identity"]["creation_time_100ns"]
    {
        return Err("actual retained positive guardian/root/live association differs".into());
    }
    facts.operations.insert("caller-token-attested".into());
    if expected["restricted"] == true {
        facts.operations.insert("restricted-token".into());
    }
    let case = descriptor["case"].as_str().ok_or("fixture case absent")?;
    let expected_case = match semantic.key.family.as_str() {
        "W-JOINT" => {
            if semantic.key.scenario == "endpoint-mismatch" {
                "endpoint-mismatch"
            } else {
                "joint"
            }
        }
        "W-TOOLCHAIN" => "toolchain",
        "W-CHURN" => "churn",
        "W-CAPACITY" => "joint",
        _ => case,
    };
    if case != expected_case {
        return Err("raw descriptor substitutes another positive recipe".into());
    }
    if matches!(case, "joint" | "churn") {
        let peer: Value = wire::decode(
            custody.bytes(
                peers
                    .get("native-tcp-peer")
                    .copied()
                    .ok_or("independently held TCP peer native edge absent")?,
            )?,
        )?;
        let fields = [
            "format",
            "revision",
            "pid",
            "birth",
            "parent_pid",
            "parent_birth",
            "native_parent_edge_observed",
            "parent_and_child_held_live",
        ];
        if peer.as_object().is_none_or(|object| {
            object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
        }) || peer["format"] != "memcordon.windows-native-tcp-peer"
            || peer["revision"] != 1
            || peer["parent_pid"].as_u64() != native.root_pid.map(u64::from)
            || peer["parent_birth"].as_u64() != native.root_birth
            || peer["native_parent_edge_observed"] != true
            || peer["parent_and_child_held_live"] != true
        {
            return Err("raw native TCP peer live ancestry/root differs".into());
        }
        let pid = peer["pid"].as_u64().ok_or("TCP peer native PID absent")?;
        let birth = peer["birth"]
            .as_u64()
            .ok_or("TCP peer native birth absent")?;
        if !identities.contains(&(pid, birth))
            || Some(pid) == native.root_pid.map(u64::from)
            || Some(birth) < native.root_birth
            || !native.held_processes.iter().any(|held| {
                u64::from(held.pid) == pid
                    && held.birth == birth
                    && held.parent_pid == native.root_pid
                    && held.parent_birth == native.root_birth
            })
        {
            return Err("raw TCP peer differs from final same held native identity/parent".into());
        }
    }
    for event in &events {
        match event.stage.as_str() {
            "tcp-conflicting-bind" => {
                if event.value != 10048i32.to_le_bytes() {
                    return Err("competing bind omitted actual address-in-use failure".into());
                }
                facts.operations.insert("tcp-conflicting-bind".into());
            }
            "tcp-listener-owned" => {
                if event.value.len() != 2 {
                    return Err("actual owned TCP port width differs".into());
                }
                let port = u16::from_le_bytes(
                    event
                        .value
                        .as_slice()
                        .try_into()
                        .map_err(|_| "port width")?,
                );
                if port == 0 {
                    return Err("actual owned TCP port absent".into());
                }
                let receipt: Value = wire::decode(
                    custody.bytes(
                        peers
                            .get("native-listener")
                            .copied()
                            .ok_or("independent native listener observation absent")?,
                    )?,
                )?;
                let fields = [
                    "format",
                    "revision",
                    "root_pid",
                    "root_creation_time_100ns",
                    "address",
                    "port",
                    "held_owner_live",
                    "native_table_owner_observed_before_and_after",
                    "conflicting_bind_win32_code",
                ];
                if receipt.as_object().is_none_or(|object| {
                    object.len() != fields.len()
                        || object.keys().any(|key| !fields.contains(&key.as_str()))
                }) || receipt["format"] != "memcordon.windows-native-listener"
                    || receipt["revision"] != 1
                    || receipt["root_pid"].as_u64() != native.root_pid.map(u64::from)
                    || receipt["root_creation_time_100ns"].as_u64() != native.root_birth
                    || receipt["address"] != "127.0.0.1"
                    || receipt["port"] != port
                    || receipt["held_owner_live"] != true
                    || receipt["native_table_owner_observed_before_and_after"] != true
                    || receipt["conflicting_bind_win32_code"] != 10048
                {
                    return Err(
                        "actual native table/listener owner/port/conflicting bind differs".into(),
                    );
                }
                facts.operations.insert("tcp-owned-listener".into());
            }
            "named-pipe-while-tcp-owned" => {
                if event.value != challenge {
                    return Err("actual pipe round-trip challenge differs".into());
                }
                let expected = frames(&[Vec::new(), vec![0, 255, 128], challenge.clone()]);
                check_peer(&peers, "named-pipe-server", &expected, custody)?;
                check_peer(&peers, "named-pipe-client", &expected, custody)?;
                facts.operations.insert("named-pipe-exchange".into());
            }
            "binary-files" => {
                check_peer(&peers, "empty-file", &[], custody)?;
                check_peer(
                    &peers,
                    "binary-file",
                    &(0..=255).collect::<Vec<u8>>(),
                    custody,
                )?;
                check_peer(&peers, "challenge-file", &challenge, custody)?;
                facts.operations.insert("allowed-file-write".into());
            }
            "toolchain-compiled" => {
                if event.value != challenge || descriptor["toolchain"].is_null() {
                    return Err("actual selected toolchain operation absent".into());
                }
                crate::windows_toolchain::validate(
                    &descriptor,
                    native,
                    input,
                    &challenge,
                    &peers,
                    custody,
                )?;
                facts.operations.insert("locked-rust-compile".into());
            }
            "toolchain-test-child-dll-complete" => {
                if event.value != challenge {
                    return Err("generated toolchain completion challenge differs".into());
                }
                check_peer(&peers, "compiled-child", &challenge, custody)?;
                check_peer(&peers, "dll-empty", &[], custody)?;
                check_peer(
                    &peers,
                    "dll-binary",
                    &(0..=255).collect::<Vec<u8>>(),
                    custody,
                )?;
                let tests = std::str::from_utf8(
                    custody.bytes(
                        peers
                            .get("compiled-test-stdout")
                            .copied()
                            .ok_or("actual generated test output absent")?,
                    )?,
                )
                .map_err(|_| "generated test output encoding differs")?;
                if !tests.lines().any(|line| {
                    line.starts_with("test result: ok.")
                        && !line.contains("0 passed;")
                        && line.contains("0 failed;")
                        && line.contains("0 ignored;")
                }) {
                    return Err("actual generated test harness omitted successful execution".into());
                }
                facts.operations.extend(
                    [
                        "compiled-tests",
                        "generated-executable",
                        "compiled-dll-loaded",
                        "generated-descendant",
                    ]
                    .map(String::from),
                );
            }
            "protected-write-denied" => {
                let denial: Value = wire::decode(&event.value)?;
                if denial.as_object().is_none_or(|object| {
                    object.len() != 2
                        || object
                            .keys()
                            .any(|field| !["path_utf16", "win32_code"].contains(&field.as_str()))
                }) || denial["win32_code"] != 5
                    || Some(event.pid) != native.root_pid
                {
                    return Err(
                        "actual protected write denial schema/native root/code differs".into(),
                    );
                }
                let paths: Vec<String> =
                    serde_json::from_value(descriptor["denied_write_paths"].clone())
                        .map_err(|error| error.to_string())?;
                if !paths.iter().any(|path| {
                    serde_json::to_value(path.encode_utf16().collect::<Vec<_>>())
                        .ok()
                        .as_ref()
                        == Some(&denial["path_utf16"])
                }) {
                    return Err("actual protected write denial targets unrelated path".into());
                }
                facts.operations.insert("protected-write-denied".into());
            }
            "tcp-peer-complete" => {
                if event.value != challenge {
                    return Err("TCP peer completion differs".into());
                }
                let mut request = frames(&[
                    b"GET /readiness HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec(),
                    vec![],
                    vec![0, 255, 128, 10],
                    challenge.clone(),
                ]);
                check_peer(&peers, "tcp-server-received", &request, custody)?;
                request = frames(&[
                    b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec(),
                    vec![],
                    vec![0, 255, 128, 10],
                    challenge.clone(),
                ]);
                check_peer(&peers, "tcp-peer-received", &request, custody)?;
                facts.operations.insert("http-exchange".into());
            }
            "sentinel-handles-excluded" if event.value == 1u32.to_le_bytes() => {
                facts
                    .operations
                    .extend(["frontend-sentinel-held", "sentinel-not-inherited"].map(String::from));
            }
            _ => {}
        }
    }
    if case == "binary-streams" {
        for (role, field) in [("stdout", "stdout"), ("stderr", "stderr")] {
            let vector: Vec<u8> =
                serde_json::from_value(descriptor[field].clone()).map_err(|e| e.to_string())?;
            if vector.len() > 65536 {
                return Err("stream input vector exceeds bound".into());
            }
            check_peer(&peers, role, &vector.repeat(128), custody)?;
        }
    } else if matches!(
        case,
        "empty-streams" | "native-argv" | "application-exit" | "envelope"
    ) {
        check_peer(&peers, "stdout", &[], custody)?;
        check_peer(&peers, "stderr", &[], custody)?;
    }
    if case == "churn" {
        if descriptor["churn_creations"] != 4096 || descriptor["churn_live"] != 63 {
            return Err("churn descriptor narrowed frozen bounds or failed to reserve the retained TCP peer within64 total".into());
        }
        for stage in ["child-created", "child-completed"] {
            let rows = events
                .iter()
                .filter(|event| event.stage == stage)
                .collect::<Vec<_>>();
            let ordinals = rows
                .iter()
                .filter_map(|event| event.ordinal)
                .collect::<BTreeSet<_>>();
            if rows.len() != 4096 || ordinals != (0..4096).collect() {
                return Err("churn creation/completion ordinal set differs".into());
            }
        }
        facts.counters.insert("churn-creations".into(), 4096);
        facts.counters.insert("churn-completions".into(), 4096);
        let held = native
            .held_processes
            .iter()
            .map(|identity| ((identity.pid, identity.birth), identity))
            .collect::<BTreeMap<_, _>>();
        if held.len() != native.held_processes.len() {
            return Err("native held churn identity set duplicates".into());
        }
        let mut created = BTreeSet::new();
        for event in events.iter().filter(|event| event.stage == "child-created") {
            let identity: Value = wire::decode(&event.value)?;
            let pid = u32::try_from(
                identity["process_id"]
                    .as_u64()
                    .ok_or("actual child process id absent")?,
            )
            .map_err(|e| e.to_string())?;
            let birth = identity["creation_time_100ns"]
                .as_u64()
                .ok_or("actual child creation time absent")?;
            if !created.insert((pid, birth))
                || held
                    .get(&(pid, birth))
                    .is_none_or(|held| !held.retirement_observed)
            {
                return Err(
                    "churn child is duplicated or lacks independently held native retirement"
                        .into(),
                );
            }
        }
        let mut maximum_depth = 0u64;
        for identity in held.values() {
            let mut current = *identity;
            let mut depth = 0u64;
            let mut seen = BTreeSet::new();
            while Some(current.pid) != native.root_pid || Some(current.birth) != native.root_birth {
                if !seen.insert((current.pid, current.birth)) || depth >= 128 {
                    return Err("native held churn ancestry cycles or exceeds bound".into());
                }
                let parent = (
                    current.parent_pid.ok_or("native child parent PID absent")?,
                    current
                        .parent_birth
                        .ok_or("native child parent birth absent")?,
                );
                if parent.1 > current.birth {
                    return Err("native child parent identity was born after child".into());
                }
                current = held
                    .get(&parent)
                    .ok_or("native churn ancestry parent was not independently held")?;
                depth += 1;
            }
            maximum_depth = maximum_depth.max(depth);
        }
        if maximum_depth < 3 {
            return Err("actual held churn ancestry omitted three generations".into());
        }
        let mut maximum_live = 0u64;
        for event in events.iter().filter(|event| event.stage == "cohort-live") {
            if event.value.len() != 4 {
                return Err("actual live cohort count width differs".into());
            }
            let leaves = u32::from_le_bytes(
                event
                    .value
                    .as_slice()
                    .try_into()
                    .map_err(|_| "cohort count width")?,
            ) as u64;
            if leaves == 0 || leaves > 63 {
                return Err("leaf cohort violates reserved peer capacity".into());
            }
            maximum_live = maximum_live.max(leaves + 1);
        }
        let mut expected_roles = BTreeSet::new();
        for event in events
            .iter()
            .filter(|event| matches!(event.stage.as_str(), "cohort-live" | "generation-live"))
        {
            let ordinal = event
                .ordinal
                .ok_or("native barrier fixture ordinal absent")?;
            let role = format!("native-{}-{ordinal}", event.stage);
            if !expected_roles.insert(role.clone()) {
                return Err("native barrier ordinal duplicated".into());
            }
            let raw: NativeBarrier = wire::decode(
                custody.bytes(
                    peers
                        .get(role.as_str())
                        .copied()
                        .ok_or("raw independently held native barrier absent")?,
                )?,
            )?;
            if raw.format != "memcordon.windows-native-churn-barrier"
                || raw.revision != 1
                || raw.stage != event.stage
                || raw.ordinal != ordinal
                || Some(raw.root_pid) != native.root_pid
                || raw.live_children == 0
                || raw.live_children > 64
                || raw.members.len() as u64 != raw.live_children + 1
            {
                return Err("raw native barrier stage/ordinal/live population differs".into());
            }
            let mut live = BTreeMap::new();
            for member in &raw.members {
                let exact = held
                    .get(&(member.pid, member.birth))
                    .ok_or("raw barrier member absent from final held native identity set")?;
                if !member.held_live_before_release
                    || !exact.retirement_observed
                    || exact.parent_pid != member.parent_pid
                    || exact.parent_birth != member.parent_birth
                    || live.insert((member.pid, member.birth), member).is_some()
                {
                    return Err("raw barrier member custody/ancestry differs".into());
                }
            }
            if !live.contains_key(&(raw.root_pid, native.root_birth.ok_or("root birth absent")?)) {
                return Err("native barrier root absent".into());
            }
            let mut depth_max = 0u64;
            for member in &raw.members {
                let mut current = member;
                let mut depth = 0u64;
                let mut seen = BTreeSet::new();
                while current.pid != raw.root_pid {
                    if !seen.insert((current.pid, current.birth)) || depth >= 128 {
                        return Err("native live barrier ancestry cycles".into());
                    }
                    let parent = (
                        current.parent_pid.ok_or("raw barrier parent absent")?,
                        current
                            .parent_birth
                            .ok_or("raw barrier parent birth absent")?,
                    );
                    if parent.1 > current.birth {
                        return Err("raw barrier parent born after child".into());
                    }
                    current = live
                        .get(&parent)
                        .copied()
                        .ok_or("raw barrier parent not held live before release")?;
                    depth += 1;
                }
                depth_max = depth_max.max(depth);
            }
            if event.stage == "generation-live" && depth_max < 3 {
                return Err("native generation barrier lacks actual depth3".into());
            }
            if event.stage == "cohort-live" {
                let leaves = u32::from_le_bytes(
                    event
                        .value
                        .as_slice()
                        .try_into()
                        .map_err(|_| "cohort width differs")?,
                ) as u64;
                if raw.live_children != leaves + 1 {
                    return Err(
                        "raw native live count differs from held cohort plus TCP peer".into(),
                    );
                }
            }
            maximum_live = maximum_live.max(raw.live_children);
        }
        if expected_roles.is_empty()
            || peers
                .keys()
                .filter(|role| {
                    role.starts_with("native-cohort-live-")
                        || role.starts_with("native-generation-live-")
                })
                .any(|role| !expected_roles.contains(*role))
        {
            return Err("native raw barrier publication ordinal set differs".into());
        }
        if maximum_live == 0 || maximum_live > 64 {
            return Err("actual churn omitted bounded live cohort evidence".into());
        }
        facts
            .counters
            .insert("churn-generations".into(), maximum_depth);
        facts
            .counters
            .insert("max-live-children".into(), maximum_live);
        facts.operations.extend(
            [
                "held-cohort-ancestry",
                "churn-creations",
                "churn-completions",
                "churn-generations",
                "max-live-children",
            ]
            .map(String::from),
        );
    }
    let _ = input;
    Ok(facts)
}

fn events(mut bytes: &[u8]) -> VerificationResult<Vec<Event>> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            return Err("fixture event length prefix truncated".into());
        }
        let length =
            u32::from_le_bytes(bytes[..4].try_into().map_err(|_| "event length width")?) as usize;
        bytes = &bytes[4..];
        if length == 0 || length > 65536 || bytes.len() < length || result.len() >= 65536 {
            return Err("fixture event frame exceeds bounds or is truncated".into());
        }
        let event: Event = wire::decode(&bytes[..length])?;
        bytes = &bytes[length..];
        if event.sequence as usize != result.len() + 1
            || event.pid == 0
            || event.stage.is_empty()
            || event.stage.len() > 128
        {
            return Err("fixture event sequence/native pid/stage differs".into());
        }
        result.push(event);
    }
    Ok(result)
}
fn frames(values: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in values {
        bytes.extend((value.len() as u32).to_le_bytes());
        bytes.extend(value);
    }
    bytes
}
fn check_peer(
    peers: &BTreeMap<&str, &str>,
    role: &str,
    expected: &[u8],
    custody: &custody::Custody,
) -> VerificationResult<()> {
    if custody.bytes(
        peers
            .get(role)
            .copied()
            .ok_or_else(|| format!("actual independent peer product missing: {role}"))?,
    )? != expected
    {
        return Err(format!(
            "actual peer bytes differ from independently known vector: {role}"
        ));
    }
    Ok(())
}
