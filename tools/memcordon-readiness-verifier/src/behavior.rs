//! Fixture effects are behavioral data, never containment or authorization.
use crate::*;
use serde_json::Value;

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
        if let Some(facts) =
            crate::linux_limits::validate_behavior(behavior, semantic, native, input, custody)?
        {
            return Ok(facts);
        }
        if let Some(facts) =
            crate::linux_isolation::validate_behavior(behavior, semantic, native, input, custody)?
        {
            return Ok(facts);
        }
        return linux(behavior, semantic, native, custody);
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
    if object.len() != allowed.len()
        || object.keys().any(|key| !allowed.contains(&key.as_str()))
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
        validate_windows_capacity_exclusions(
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
            "sentinel-handles-excluded" => {
                if event.value == 1u32.to_le_bytes() {
                    facts.operations.extend(
                        ["frontend-sentinel-held", "sentinel-not-inherited"].map(String::from),
                    );
                }
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

fn linux(
    behavior: &FixtureBehavior,
    semantic: &SemanticObservation,
    native: &NativeObservation,
    custody: &custody::Custody,
) -> VerificationResult<Facts> {
    let mut facts = Facts {
        operations: BTreeSet::new(),
        counters: BTreeMap::new(),
    };
    let bytes = custody.bytes(&behavior.transcript)?;
    let binding: Value = wire::decode(
        custody.bytes(
            behavior
                .native_binding
                .as_deref()
                .ok_or("Linux behavior lacks independently held native PID mapping")?,
        )?,
    )?;
    let local = binding["target"]["namespace_pids"]
        .as_array()
        .and_then(|pids| pids.last())
        .and_then(Value::as_u64)
        .ok_or("native target namespace PID mapping absent")?;
    if binding["target"]["process_id"].as_u64() != native.root_pid.map(u64::from)
        || binding["target"]["birth"].as_u64() != native.root_birth
        || binding["run_id"] != native.run_id
    {
        return Err("behavioral namespace PID mapping differs from held host root".into());
    }
    if bytes.is_empty() || !bytes.ends_with(b"\n") {
        return Err("Linux behavioral transcript missing/truncated".into());
    }
    let mut root_first_child = None;
    let mut host_denial = None;
    let mut private_unix_positive = None;
    let mut descriptor_isolation = None;
    let mut argv_observation = None;
    let mut authority_denial = None;
    let mut neighboring_sockets = None;
    let mut cooperation_held = None;
    let mut cooperation_complete = None;
    let mut abstract_held = None;
    let build = (semantic.key.family == "L-MIX-01"
        && semantic.key.scenario == "joint-build-tcp-unix-http")
        || (semantic.key.family == "L-IMG-03"
            && ["dynamic-rust-build-and-exec", "image-only-entrypoint"]
                .contains(&semantic.key.scenario.as_str()));
    let mut build_rows = BTreeMap::new();
    for (ordinal, line) in bytes
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .enumerate()
    {
        let row: Value = wire::decode(line)?;
        if row.as_object().is_none_or(|object| {
            object.len() != 8
                || object.keys().any(|key| {
                    ![
                        "format",
                        "revision",
                        "sequence",
                        "challenge",
                        "root_pid",
                        "root_birth",
                        "operation",
                        "observation",
                    ]
                    .contains(&key.as_str())
                })
        }) || row["format"] != "memcordon.linux-readiness-transcript"
            || row["revision"] != 1
            || row["sequence"] != ordinal as u64 + 1
            || row["challenge"] != hex::encode(custody.bytes(&semantic.challenge)?)
            || row["root_pid"].as_u64() != Some(local)
            || row["root_birth"].as_u64() != native.root_birth
        {
            return Err("Linux raw behavioral row association differs".into());
        }
        if build {
            let operation = row["operation"]
                .as_str()
                .ok_or("Linux build operation encoding differs")?;
            if build_rows
                .insert(operation.to_owned(), row["observation"].clone())
                .is_some()
            {
                return Err("Linux Joint build raw operation duplicated".into());
            }
        }
        if row["operation"] == "bind-zero-and-competing-bind"
            && row["observation"]["native_errno"] == 98
        {
            facts
                .operations
                .extend(["tcp-owned-listener", "tcp-conflicting-bind"].map(String::from));
        }
        if row["operation"] == "application-endpoint-mismatch" {
            if semantic.key.family != "L-MIX-02"
                || semantic.key.scenario != "endpoint-mismatch"
                || native.origin != OutcomeOrigin::ApplicationRefusal
                || native.target_status != Some(42)
                || native.application_stage.as_deref() != Some("endpoint-policy")
            {
                return Err("endpoint application refusal substituted another native cause".into());
            }
            let raw: Value = wire::decode(
                custody.bytes(
                    behavior
                        .peer_artifacts
                        .iter()
                        .find(|peer| peer.role == "native-endpoint-mismatch")
                        .ok_or("independent native retained listeners absent")?
                        .path
                        .as_str(),
                )?,
            )?;
            validate_linux_endpoint_mismatch(
                &row["observation"],
                &raw,
                native.root_pid.ok_or("endpoint held root absent")?,
                native.root_birth.ok_or("endpoint held root birth absent")?,
                &binding["target"]["network"],
                native
                    .attempt_id
                    .as_deref()
                    .ok_or("endpoint native admission absent")?,
                custody.bytes(&semantic.challenge)?,
            )?;
            let probe = semantic
                .negative_probe
                .as_ref()
                .ok_or("endpoint application refusal receipt absent")?;
            if probe.receipt != behavior.transcript
                || probe.domain != "application"
                || probe.native_code != 42
                || probe.stage != "endpoint-mismatch"
            {
                return Err(
                    "endpoint negative observation differs from actual typed application refusal"
                        .into(),
                );
            }
            facts.operations.extend(
                [
                    "tcp-owned-listener",
                    "second-reserved-listener",
                    "application-endpoint-refusal",
                ]
                .map(String::from),
            );
        }
        if row["operation"] == "scm-rights-regular-and-listener" {
            let observation = &row["observation"];
            let fields = [
                "file_bytes",
                "endpoint",
                "network_bytes",
                "file_device",
                "file_inode",
                "received_file_device",
                "received_file_inode",
                "listener_device",
                "listener_inode",
                "received_listener_device",
                "received_listener_inode",
            ];
            if observation.as_object().is_none_or(|object| {
                object.len() != fields.len()
                    || object.keys().any(|key| !fields.contains(&key.as_str()))
            }) {
                return Err("native descriptor transfer raw schema differs".into());
            }
            let endpoint: std::net::SocketAddr = observation["endpoint"]
                .as_str()
                .ok_or("transferred TCP endpoint absent")?
                .parse()
                .map_err(|_| "transferred TCP endpoint malformed")?;
            if endpoint.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                || endpoint.port() == 0
            {
                return Err(
                    "transferred listener is not an owned private loopback bind-zero socket".into(),
                );
            }
            let file: Vec<u8> = serde_json::from_value(observation["file_bytes"].clone())
                .map_err(|error| error.to_string())?;
            let network: Vec<u8> = serde_json::from_value(observation["network_bytes"].clone())
                .map_err(|error| error.to_string())?;
            if file != b"descriptor-readiness" || network != b"rights-listener" {
                return Err("actual transferred descriptor byte effects differ".into());
            }
            for role in ["file", "listener"] {
                let device = format!("{role}_device");
                let inode = format!("{role}_inode");
                if observation[&device] != observation[format!("received_{device}")]
                    || observation[&inode] != observation[format!("received_{inode}")]
                    || observation[&inode].as_u64().is_none_or(|value| value == 0)
                {
                    return Err("transferred native descriptor identity differs".into());
                }
            }
            let peers = behavior
                .peer_artifacts
                .iter()
                .map(|artifact| (artifact.role.as_str(), artifact.path.as_str()))
                .collect::<BTreeMap<_, _>>();
            if custody.bytes(
                peers
                    .get("transferred-file")
                    .copied()
                    .ok_or("transferred file product absent")?,
            )? != file
                || custody.bytes(
                    peers
                        .get("tcp")
                        .copied()
                        .ok_or("transferred listener received bytes absent")?,
                )? != network
            {
                return Err("raw transferred descriptor transcript/product mismatch".into());
            }
            facts
                .operations
                .extend(["scm-rights-listener", "scm-rights-private-file"].map(String::from));
        }
        if row["operation"] == "empty-message-exchanged" {
            let payload: Vec<u8> = serde_json::from_value(row["observation"]["payload"].clone())
                .map_err(|error| error.to_string())?;
            let frame: Vec<u8> =
                serde_json::from_value(row["observation"]["received_length_prefix"].clone())
                    .map_err(|error| error.to_string())?;
            let peer = behavior
                .peer_artifacts
                .iter()
                .find(|artifact| artifact.role == "message")
                .ok_or("actual empty message product absent")?;
            if !payload.is_empty()
                || frame != [0, 0, 0, 0]
                || !custody.bytes(&peer.path)?.is_empty()
            {
                return Err("actual framed empty message is not zero length".into());
            }
            facts.operations.insert("empty-message-exchanged".into());
        }
        if [
            "other-attempt-abstract-held",
            "other-attempt-abstract-released",
        ]
        .iter()
        .any(|operation| row["operation"] == *operation)
            && semantic.key.family == "L-ISO-03"
            && semantic.key.scenario == "own-abstract-positive"
        {
            let observation = &row["observation"];
            let fields = [
                "name",
                "socket_inode",
                "network_namespace_inode",
                "baseline_client_connected",
                "baseline_server_accepted",
                "bytes",
            ];
            let expected = format!(
                "memcordon-readiness-{}",
                hex::encode(custody.bytes(&semantic.challenge)?)
            );
            if observation.as_object().is_none_or(|object| {
                object.len() != fields.len()
                    || object.keys().any(|key| !fields.contains(&key.as_str()))
            }) || serde_json::from_value::<Vec<u8>>(observation["name"].clone())
                .map_err(|error| error.to_string())?
                != expected.as_bytes()
                || observation["socket_inode"]
                    .as_u64()
                    .is_none_or(|inode| inode == 0)
                || observation["network_namespace_inode"] != binding["target"]["network"]["inode"]
                || observation["baseline_client_connected"] != true
                || observation["baseline_server_accepted"] != true
                || serde_json::from_value::<Vec<u8>>(observation["bytes"].clone())
                    .map_err(|error| error.to_string())?
                    != b"abstract-unix-readiness"
                || custody.bytes(
                    &behavior
                        .peer_artifacts
                        .iter()
                        .find(|artifact| artifact.role == "unix-abstract")
                        .ok_or("held own abstract original bytes absent")?
                        .path,
                )? != b"abstract-unix-readiness"
            {
                return Err("held own abstract original native listener differs".into());
            }
            if row["operation"] == "other-attempt-abstract-held" {
                if ordinal != 0 || abstract_held.replace(observation.clone()).is_some() {
                    return Err("held abstract original barrier duplicated".into());
                }
            } else {
                if ordinal != 1
                    || abstract_held.as_ref() != Some(observation)
                    || bytes
                        .split(|byte| *byte == b'\n')
                        .filter(|line| !line.is_empty())
                        .count()
                        != 2
                {
                    return Err("held abstract original release differs".into());
                }
                facts.operations.insert("unix-abstract-exchange".into());
            }
        }
        if row["operation"] == "unix-abstract-round-trip"
            && semantic.key.family == "L-ISO-03"
            && semantic.key.scenario == "own-abstract-positive"
        {
            let observation = &row["observation"];
            if observation.as_object().is_none_or(|object| {
                object.len() != 2 || !object.contains_key("name") || !object.contains_key("bytes")
            }) {
                return Err("own abstract raw exchange schema differs".into());
            }
            let name: Vec<u8> = serde_json::from_value(observation["name"].clone())
                .map_err(|error| error.to_string())?;
            let received: Vec<u8> = serde_json::from_value(observation["bytes"].clone())
                .map_err(|error| error.to_string())?;
            let peer = behavior
                .peer_artifacts
                .iter()
                .find(|artifact| artifact.role == "unix-abstract")
                .ok_or("actual own abstract product absent")?;
            if name != hex::encode(custody.bytes(&semantic.challenge)?).as_bytes()
                || received != b"abstract-unix-readiness"
                || custody.bytes(&peer.path)? != received
            {
                return Err("actual own abstract name/received product differs".into());
            }
            facts.operations.insert("unix-abstract-exchange".into());
        }
        if row["operation"] == "same-attempt-cooperation-held" {
            if cooperation_held
                .replace(row["observation"].clone())
                .is_some()
            {
                return Err("cooperation live barrier repeated".into());
            }
        }
        if row["operation"] == "same-attempt-cooperation-complete" {
            if cooperation_complete
                .replace(row["observation"].clone())
                .is_some()
            {
                return Err("cooperation completion repeated".into());
            }
        }
        if row["operation"] == "root-exiting-before-held-descendant" {
            if root_first_child
                .replace(row["observation"].clone())
                .is_some()
            {
                return Err("root-first fixture repeated its held descendant identity".into());
            }
        }
        if row["operation"] == "private-unix-pair-positive"
            && private_unix_positive
                .replace(row["observation"].clone())
                .is_some()
        {
            return Err("private Unix pair positive repeated".into());
        }
        if row["operation"] == "native-descriptor-isolation"
            && descriptor_isolation
                .replace(row["observation"].clone())
                .is_some()
        {
            return Err("native descriptor isolation probe repeated".into());
        }
        if row["operation"] == "forbidden-tcp-denied"
            || row["operation"] == "forbidden-abstract-denied"
            || row["operation"] == "forbidden-unix-path-denied"
        {
            if host_denial
                .replace((row["operation"].clone(), row["observation"].clone()))
                .is_some()
            {
                return Err("host authority probe repeated its native denial".into());
            }
        }
        if row["operation"] == "native-argv-observed"
            && argv_observation
                .replace(row["observation"].clone())
                .is_some()
        {
            return Err("actual native argv observation repeated".into());
        }
        if row["operation"] == "native-authority-denied"
            && authority_denial
                .replace(row["observation"].clone())
                .is_some()
        {
            return Err("selected native authority denial repeated".into());
        }
        if row["operation"] == "neighboring-permitted-sockets"
            && neighboring_sockets
                .replace(row["observation"].clone())
                .is_some()
        {
            return Err("neighboring permitted socket baseline repeated".into());
        }
    }
    if semantic.key.family == "L-MIX-04" && semantic.key.scenario == "cooperation" {
        let held = cooperation_held.ok_or("cooperation held child barrier absent")?;
        let complete = cooperation_complete.ok_or("cooperation child completion absent")?;
        let fields = [
            "pid",
            "birth",
            "endpoint",
            "server_received",
            "peer_transcript",
            "native_status",
        ];
        if complete.as_object().is_none_or(|object| {
            object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
        }) || held["pid"] != complete["pid"]
            || held["birth"] != complete["birth"]
            || held["endpoint"] != complete["endpoint"]
            || complete["native_status"] != 0
        {
            return Err("cooperation held/completed child association differs".into());
        }
        let endpoint: std::net::SocketAddr = complete["endpoint"]
            .as_str()
            .ok_or("cooperation endpoint absent")?
            .parse()
            .map_err(|_| "cooperation endpoint malformed")?;
        if !endpoint.is_ipv4() || !endpoint.ip().is_loopback() || endpoint.port() == 0 {
            return Err("cooperation endpoint not private loopback bind0".into());
        }
        let expected = hex::encode(custody.bytes(&semantic.challenge)?).into_bytes();
        let server: Vec<u8> = serde_json::from_value(complete["server_received"].clone())
            .map_err(|error| error.to_string())?;
        let peer_bytes: Vec<u8> = serde_json::from_value(complete["peer_transcript"].clone())
            .map_err(|error| error.to_string())?;
        let peer: Value = wire::decode(&peer_bytes)?;
        if peer["format"] != "memcordon.linux-readiness-transcript"
            || peer["revision"] != 1
            || peer["sequence"] != 2
            || peer["challenge"] != hex::encode(custody.bytes(&semantic.challenge)?)
            || peer["root_pid"] != complete["pid"]
            || peer["root_birth"] != complete["birth"]
            || peer["operation"] != "cooperation-peer-received"
            || peer["observation"]["endpoint"] != complete["endpoint"]
            || serde_json::from_value::<Vec<u8>>(peer["observation"]["bytes"].clone())
                .map_err(|error| error.to_string())?
                != expected
            || server != expected
        {
            return Err(
                "actual two-process cooperation received bytes/child transcript differ".into(),
            );
        }
        let retired: Value = wire::decode(
            custody.bytes(
                behavior
                    .peer_artifacts
                    .iter()
                    .find(|peer| peer.role == "native-retirement")
                    .ok_or("cooperation native family receipt absent")?
                    .path
                    .as_str(),
            )?,
        )?;
        let member = retired["namespace_members"]
            .as_array()
            .ok_or("cooperation child namespace mapping absent")?
            .iter()
            .find(|member| {
                member["namespace_pid"] == complete["pid"] && member["birth"] == complete["birth"]
            })
            .ok_or("cooperation child lacks independently held namespace mapping")?;
        let identity = native
            .held_processes
            .iter()
            .find(|identity| {
                Some(u64::from(identity.pid)) == member["pid"].as_u64()
                    && Some(identity.birth) == member["birth"].as_u64()
            })
            .ok_or("cooperation child held native owner absent")?;
        if retired["format"] != "memcordon.linux-held-family-retirement"
            || retired["revision"] != 1
            || retired["run_id"] != native.run_id
            || retired["lease_id"].as_str() != native.lease_id.as_deref()
            || retired["attempt_id"].as_str() != native.attempt_id.as_deref()
            || retired["aggregate_empty"] != true
            || !identity.retirement_observed
            || identity.parent_pid != native.root_pid
            || identity.parent_birth != native.root_birth
            || retired["descendants"]
                .as_array()
                .is_none_or(|descendants| descendants.len() != 1)
            || retired["descendants"][0]
                != serde_json::to_value(identity).map_err(|error| error.to_string())?
        {
            return Err(
                "cooperation peer native parent/retirement differs from same attempt".into(),
            );
        }
        let product = behavior
            .peer_artifacts
            .iter()
            .find(|peer| peer.role == "cooperation")
            .ok_or("actual cooperation product absent")?;
        if custody.bytes(&product.path)? != expected {
            return Err("cooperation product differs from actual received challenge".into());
        }
        facts.operations.insert("same-attempt-cooperation".into());
    }
    if (semantic.key.family == "L-ISO-01"
        && ["ipv6", "udp", "raw", "packet", "netlink"].contains(&semantic.key.scenario.as_str()))
        || (semantic.key.family == "L-ISO-05"
            && ["pidfd-getfd", "ptrace", "namespace-entry"]
                .contains(&semantic.key.scenario.as_str()))
    {
        let denial =
            authority_denial.ok_or("actual selected native authority syscall denial absent")?;
        let permitted = neighboring_sockets.ok_or("neighboring actual permitted sockets absent")?;
        let expected_errno = match semantic.key.scenario.as_str() {
            "ipv6" | "packet" | "netlink" => 97,
            "udp" | "raw" => 93,
            "pidfd-getfd" | "ptrace" | "namespace-entry" => 1,
            _ => return Err("unknown authority errno scenario".into()),
        };
        if denial.as_object().is_none_or(|object| {
            object.len() != 3
                || object
                    .keys()
                    .any(|key| !["probe", "native_errno", "result"].contains(&key.as_str()))
        }) || denial["probe"] != semantic.key.scenario
            || denial["native_errno"] != expected_errno
            || denial["result"] != -1
            || permitted.as_object().is_none_or(|object| {
                object.len() != 2
                    || !object.contains_key("tcp_endpoint")
                    || !object.contains_key("unix_bytes")
            })
        {
            return Err(
                "actual authority syscall/native errno or neighboring baseline differs".into(),
            );
        }
        let endpoint: std::net::SocketAddr = permitted["tcp_endpoint"]
            .as_str()
            .ok_or("neighbor TCP endpoint absent")?
            .parse()
            .map_err(|_| "neighbor TCP endpoint malformed")?;
        let received: Vec<u8> = serde_json::from_value(permitted["unix_bytes"].clone())
            .map_err(|error| error.to_string())?;
        if endpoint.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
            || endpoint.port() == 0
            || received != b"positive"
        {
            return Err("native denial omitted neighboring real permitted socket effects".into());
        }
        let probe = semantic
            .negative_probe
            .as_ref()
            .ok_or("authority denial vector absent")?;
        if probe.receipt != behavior.transcript
            || probe.stage != semantic.key.scenario
            || probe.domain != "linux"
            || probe.native_code != expected_errno
        {
            return Err("actual authority denial differs from persisted selected errno".into());
        }
        facts.operations.insert("native-authority-probe".into());
    }
    if semantic.key.family == "C-IO" && semantic.key.scenario == "native-argv" {
        let observed = argv_observation.ok_or("actual native argv transcript absent")?;
        let arguments: Vec<Vec<u8>> =
            serde_json::from_value(observed["argv"].clone()).map_err(|error| error.to_string())?;
        let peer = behavior
            .peer_artifacts
            .iter()
            .find(|artifact| artifact.role == "native-argv")
            .ok_or("actual native argv product absent")?;
        let actual: NativeArguments = wire::decode(custody.bytes(&peer.path)?)?;
        if observed["native_exit_status"] != 0
            || serde_json::to_value(actual).map_err(|error| error.to_string())?
                != serde_json::to_value(NativeArguments::UnixBytes(arguments))
                    .map_err(|error| error.to_string())?
        {
            return Err("actual native argv transcript/product differs".into());
        }
    }
    if semantic.key.family == "L-ISO-02"
        && ["host-run-socket", "host-temp-socket"].contains(&semantic.key.scenario.as_str())
    {
        let peer = |role: &str| {
            behavior
                .peer_artifacts
                .iter()
                .find(|artifact| artifact.role == role)
                .ok_or("original host pathname socket peer absent")
        };
        let canary: Value = wire::decode(custody.bytes(&peer("host-path-socket-canary")?.path)?)?;
        let intent: Value = wire::decode(custody.bytes(&peer("host-path-socket-intent")?.path)?)?;
        let allocation: Value =
            wire::decode(custody.bytes(&peer("host-path-socket-allocation")?.path)?)?;
        let closed = |value: &Value, fields: &[&str]| {
            value.as_object().is_some_and(|object| {
                object.len() == fields.len()
                    && object.keys().all(|key| fields.contains(&key.as_str()))
            })
        };
        if !closed(
            &canary,
            &[
                "format",
                "revision",
                "original",
                "parent",
                "named_absence_errno",
                "listener_closed",
                "parent_closed",
            ],
        ) || !closed(
            &intent,
            &["format", "revision", "kind", "path", "challenge", "parent"],
        ) || !closed(
            &allocation,
            &[
                "format",
                "revision",
                "path",
                "device",
                "inode",
                "uid",
                "gid",
                "nlink",
                "intent_sha256",
            ],
        ) || !closed(
            &canary["original"],
            &[
                "path",
                "device",
                "inode",
                "uid",
                "gid",
                "mode",
                "nlink",
                "listener_device",
                "listener_inode",
                "bytes",
                "kind",
                "peer",
                "network_namespace_inode",
            ],
        ) || !closed(&canary["original"]["peer"], &["pid", "birth", "uid", "gid"])
            || !closed(
                &canary["parent"],
                &["path", "device", "inode", "uid", "mode"],
            )
            || !closed(
                &intent["parent"],
                &["path", "device", "inode", "uid", "mode"],
            )
        {
            return Err("host pathname socket original schema differs".into());
        }
        let original = &canary["original"];
        let parent = &canary["parent"];
        let challenge = hex::encode(custody.bytes(&semantic.challenge)?);
        let parent_path = if semantic.key.scenario == "host-run-socket" {
            "/run"
        } else {
            "/tmp"
        };
        let path = format!("{parent_path}/memcordon-readiness-{challenge}.sock");
        let actual_bytes: Vec<u8> =
            serde_json::from_value(original["bytes"].clone()).map_err(|error| error.to_string())?;
        if allocation["format"] != "memcordon.linux-host-path-socket-allocation"
            || allocation["revision"] != 1
            || allocation["intent_sha256"]
                != crate::sha256(custody.bytes(&peer("host-path-socket-intent")?.path)?)
            || ["path", "device", "inode", "uid", "gid", "nlink"]
                .iter()
                .any(|field| allocation[*field] != original[*field])
        {
            return Err(
                "host socket completed canary differs from original native allocation".into(),
            );
        }
        if canary["format"] != "memcordon.linux-host-path-socket-canary"
            || canary["revision"] != 1
            || intent["format"] != "memcordon.linux-host-path-socket-intent"
            || intent["revision"] != 1
            || intent["challenge"] != challenge
            || intent["kind"] != semantic.key.scenario
            || original["kind"] != semantic.key.scenario
            || original["path"] != path
            || intent["path"] != path
            || parent["path"] != parent_path
            || intent["parent"] != *parent
            || actual_bytes != challenge.as_bytes()
            || original["uid"] != 0
            || original["gid"] != 0
            || original["nlink"] != 1
            || parent["uid"] != 0
            || original["peer"]["pid"] != binding["observer"]["pid"]
            || original["peer"]["birth"] != binding["observer"]["birth"]
            || original["peer"]["pid"]
                .as_u64()
                .is_none_or(|pid| pid == 0 || pid > i32::MAX as u64)
            || original["peer"]["birth"]
                .as_u64()
                .is_none_or(|birth| birth == 0)
            || original["peer"]["uid"] != 0
            || original["peer"]["gid"] != 0
            || canary["named_absence_errno"] != 2
            || canary["listener_closed"] != true
            || canary["parent_closed"] != true
        {
            return Err(
                "host pathname socket crosses original acquisition/positive/retirement".into(),
            );
        }
        let mode = original["mode"]
            .as_u64()
            .ok_or("host socket native mode absent")?;
        let parent_mode = parent["mode"]
            .as_u64()
            .ok_or("host socket parent native mode absent")?;
        if mode & 0o170000 != 0o140000
            || mode & 0o777 != 0o666
            || parent_mode & 0o170000 != 0o040000
            || (parent_mode & 0o022 != 0 && !(parent_path == "/tmp" && parent_mode & 0o1000 != 0))
            || [original, parent].iter().any(|value| {
                ["device", "inode"]
                    .iter()
                    .any(|field| value[*field].as_u64().is_none_or(|value| value == 0))
            })
            || ["listener_device", "listener_inode"]
                .iter()
                .any(|field| original[*field].as_u64().is_none_or(|value| value == 0))
        {
            return Err("host pathname socket native object/parent custody malformed".into());
        }
        let host_namespace = original["network_namespace_inode"]
            .as_u64()
            .filter(|value| *value > 0)
            .ok_or("host Unix socket namespace absent")?;
        if binding["caller"]["network"]["inode"].as_u64() != Some(host_namespace)
            || binding["target"]["network"]["inode"]
                .as_u64()
                .is_none_or(|value| value == 0 || value == host_namespace)
        {
            return Err("host Unix socket namespace reassociated".into());
        }
        let (operation, denial) = host_denial
            .take()
            .ok_or("host pathname socket actual native denial absent")?;
        let code = denial["native_errno"]
            .as_i64()
            .ok_or("host pathname socket errno absent")?;
        let probe = semantic
            .negative_probe
            .as_ref()
            .ok_or("host pathname socket independent denial projection absent")?;
        let positive = private_unix_positive
            .take()
            .ok_or("host socket probe omitted private Unix pair positive")?;
        if operation != "forbidden-unix-path-denied"
            || !closed(&denial, &["path", "native_errno"])
            || denial["path"] != path
            || ![1, 2, 13, 20, 111].contains(&code)
            || probe.stage != semantic.key.scenario
            || probe.domain != "linux"
            || probe.native_code != code
            || probe.receipt != behavior.transcript
            || !closed(&positive, &["bytes"])
            || positive["bytes"] != original["bytes"]
        {
            return Err("host pathname socket denial/private positive substituted".into());
        }
        facts.operations.insert("native-authority-probe".into());
    }
    if semantic.key.family == "L-ISO-05"
        && ["stdio-host-socket", "extra-host-fd"].contains(&semantic.key.scenario.as_str())
    {
        let closed = |value: &Value, fields: &[&str]| {
            value.as_object().is_some_and(|object| {
                object.len() == fields.len()
                    && object.keys().all(|key| fields.contains(&key.as_str()))
            })
        };
        let peer = behavior
            .peer_artifacts
            .iter()
            .find(|artifact| artifact.role == "host-socket-descriptor")
            .ok_or("original hostile host socket descriptor peer absent")?;
        let retired: Value = wire::decode(custody.bytes(&peer.path)?)?;
        let original = &retired["original"];
        if !closed(
            &retired,
            &[
                "format",
                "revision",
                "original",
                "source_closed",
                "peer_closed",
                "native_errno",
            ],
        ) || retired["format"] != "memcordon.linux-host-socket-descriptor-retired"
            || retired["revision"] != 1
            || retired["source_closed"] != true
            || retired["peer_closed"] != true
            || !retired["native_errno"].is_null()
            || !closed(
                original,
                &[
                    "format",
                    "revision",
                    "descriptor",
                    "frontend",
                    "source",
                    "peer",
                    "source_link",
                    "fdinfo",
                    "observer",
                    "host_network",
                ],
            )
            || original["format"] != "memcordon.linux-host-socket-descriptor"
            || original["revision"] != 1
            || original["descriptor"]
                != if semantic.key.scenario == "stdio-host-socket" {
                    0
                } else {
                    128
                }
        {
            return Err("host socket original handoff/closure schema differs".into());
        }
        let binding = behavior
            .native_binding
            .as_ref()
            .ok_or("host descriptor original native preparation binding absent")?;
        let prepared: Value = wire::decode(custody.bytes(binding)?)?;
        if original["frontend"] != prepared["caller"]
            || original["observer"] != prepared["observer"]
            || original["host_network"] != prepared["caller"]["network"]
            || prepared["caller"]["network"] == prepared["target"]["network"]
        {
            return Err(
                "host descriptor original caller/observer/private namespace association differs"
                    .into(),
            );
        }
        for name in ["source", "peer"] {
            let native = &original[name];
            if !closed(native, &["device", "inode", "mode"])
                || native["device"].as_u64().is_none_or(|value| value == 0)
                || native["inode"].as_u64().is_none_or(|value| value == 0)
                || native["mode"]
                    .as_u64()
                    .is_none_or(|mode| mode & 0o170000 != 0o140000)
            {
                return Err("host descriptor actual held socket source absent".into());
            }
        }
        if original["source"]["inode"] == original["peer"]["inode"] {
            return Err("host socket source substituted its own external peer".into());
        }
        let link: Vec<u8> = serde_json::from_value(original["source_link"].clone())
            .map_err(|error| error.to_string())?;
        if link
            != format!(
                "socket:[{}]",
                original["source"]["inode"]
                    .as_u64()
                    .ok_or("host socket inode absent")?
            )
            .as_bytes()
        {
            return Err("actual frontend socket named source differs".into());
        }
        let fdinfo: Vec<u8> = serde_json::from_value(original["fdinfo"].clone())
            .map_err(|error| error.to_string())?;
        if fdinfo.len() > 4096 {
            return Err("host descriptor fdinfo unbounded".into());
        }
        let text = std::str::from_utf8(&fdinfo).map_err(|error| error.to_string())?;
        let mut entries = std::collections::BTreeMap::new();
        for line in text.lines() {
            let (key, value) = line
                .split_once(':')
                .ok_or("host descriptor native fdinfo malformed")?;
            if entries.insert(key, value.trim()).is_some() {
                return Err("host descriptor fdinfo duplicate".into());
            }
        }
        if entries
            .keys()
            .any(|name| !["pos", "flags", "mnt_id", "ino", "scm_fds"].contains(name))
            || entries
                .get("ino")
                .and_then(|value| value.parse::<u64>().ok())
                != original["source"]["inode"].as_u64()
            || entries.get("pos") != Some(&"0")
            || entries
                .get("flags")
                .and_then(|value| u64::from_str_radix(value, 8).ok())
                != Some(2)
            || entries
                .get("mnt_id")
                .and_then(|value| value.parse::<u64>().ok())
                .is_none_or(|value| value == 0)
            || entries.get("scm_fds").is_some_and(|value| *value != "0")
        {
            return Err("host descriptor original inode/flags fdinfo differs".into());
        }
        let observed =
            descriptor_isolation.ok_or("actual target descriptor syscall probe absent")?;
        if !closed(&observed, &["stdio", "extra_descriptor", "native_errno"])
            || observed["extra_descriptor"] != 128
            || observed["native_errno"] != 9
        {
            return Err("actual target extra host descriptor did not close".into());
        }
        let stdio = observed["stdio"]
            .as_array()
            .filter(|rows| rows.len() == 3)
            .ok_or("actual target three byte pipes absent")?;
        let mut identities = std::collections::BTreeSet::new();
        for (descriptor, native) in stdio.iter().enumerate() {
            if !closed(native, &["descriptor", "device", "inode", "mode"])
                || native["descriptor"] != descriptor as u64
                || native["device"].as_u64().is_none_or(|value| value == 0)
                || native["inode"].as_u64().is_none_or(|value| value == 0)
                || native["mode"]
                    .as_u64()
                    .is_none_or(|mode| mode & 0o170000 != 0o010000)
                || !identities.insert((native["device"].as_u64(), native["inode"].as_u64()))
            {
                return Err(
                    "target stdio substituted external sockets or shared descriptor authority"
                        .into(),
                );
            }
        }
        let positive = private_unix_positive
            .take()
            .ok_or("host descriptor probe omitted actual private Unix pair positive")?;
        if !closed(&positive, &["bytes"])
            || positive["bytes"]
                != serde_json::to_value(hex::encode(custody.bytes(&semantic.challenge)?).as_bytes())
                    .map_err(|error| error.to_string())?
        {
            return Err("host descriptor neighboring private pair bytes differ".into());
        }
        facts.operations.insert("native-authority-probe".into());
    }
    if (semantic.key.family == "L-ISO-01"
        && ["host-tcp", "nonloopback"].contains(&semantic.key.scenario.as_str()))
        || (semantic.key.family == "L-ISO-03" && semantic.key.scenario == "host-abstract")
    {
        let tcp = semantic.key.family == "L-ISO-01";
        let role = if tcp {
            "host-tcp-canary"
        } else {
            "host-abstract-canary"
        };
        let path = behavior
            .peer_artifacts
            .iter()
            .find(|artifact| artifact.role == role)
            .ok_or("independently held host canary absent")?;
        let canary: Value = wire::decode(custody.bytes(&path.path)?)?;
        let (operation, denial) =
            host_denial.ok_or("actual host authority native denial absent")?;
        let expected = if tcp {
            "forbidden-tcp-denied"
        } else {
            "forbidden-abstract-denied"
        };
        let field = if tcp { "endpoint" } else { "name" };
        let fields = [
            "format",
            "revision",
            "challenge",
            field,
            "socket_inode",
            "network_namespace_inode",
            "baseline_client_connected",
            "baseline_server_accepted",
        ];
        if canary.as_object().is_none_or(|object| {
            object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
        }) || denial.as_object().is_none_or(|object| {
            object.len() != 2 || !object.contains_key(field) || !object.contains_key("native_errno")
        }) {
            return Err("host authority canary/denial raw schema differs".into());
        }
        if tcp {
            let endpoint: std::net::SocketAddr = canary[field]
                .as_str()
                .ok_or("host TCP endpoint absent")?
                .parse()
                .map_err(|_| "host TCP endpoint malformed")?;
            let address_ok = match endpoint.ip() {
                std::net::IpAddr::V4(ip) => {
                    if semantic.key.scenario == "nonloopback" {
                        !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast()
                    } else {
                        ip == std::net::Ipv4Addr::LOCALHOST
                    }
                }
                _ => false,
            };
            if !address_ok || endpoint.port() == 0 {
                return Err(
                    "host TCP canary differs from its actual selected native bind-zero allocation"
                        .into(),
                );
            }
        } else {
            let name: Vec<u8> =
                serde_json::from_value(canary[field].clone()).map_err(|error| error.to_string())?;
            if name
                != format!(
                    "memcordon-readiness-{}",
                    hex::encode(custody.bytes(&semantic.challenge)?)
                )
                .as_bytes()
            {
                return Err("host abstract canary name differs from fresh challenge".into());
            }
        }
        if operation != expected
            || canary["format"]
                != if tcp {
                    "memcordon.linux-host-tcp-canary"
                } else {
                    "memcordon.linux-host-abstract-canary"
                }
            || canary["revision"] != 1
            || canary["challenge"] != hex::encode(custody.bytes(&semantic.challenge)?)
            || canary["baseline_client_connected"] != true
            || canary["baseline_server_accepted"] != true
            || canary["socket_inode"]
                .as_u64()
                .is_none_or(|inode| inode == 0)
            || canary[field] != denial[field]
        {
            return Err(
                "actual denied host endpoint differs from independently held live baseline".into(),
            );
        }
        let host_namespace = canary["network_namespace_inode"]
            .as_u64()
            .ok_or("host listener native namespace absent")?;
        if host_namespace == 0
            || binding["target"]["network"]["inode"]
                .as_u64()
                .is_none_or(|inode| inode == 0 || inode == host_namespace)
            || binding["caller"]["network"]["inode"].as_u64() != Some(host_namespace)
        {
            return Err(
                "held host listener and fresh target network namespace association differs".into(),
            );
        }
        let probe = semantic
            .negative_probe
            .as_ref()
            .ok_or("host denial vector absent")?;
        let code = denial["native_errno"]
            .as_i64()
            .ok_or("host denial errno absent")?;
        if probe.receipt != behavior.transcript
            || probe.stage != semantic.key.scenario
            || probe.domain != "linux"
            || probe.native_code != code
            || !(if tcp {
                [1, 101, 111, 113].contains(&code)
            } else {
                [1, 13, 111].contains(&code)
            })
        {
            return Err("host native errno differs from exact source-backed denial".into());
        }
        facts.operations.insert("native-authority-probe".into());
    }
    if (semantic.key.family == "L-LIFE-01"
        && semantic.key.scenario == "root-first-resource-descendant")
        || (semantic.key.family == "C-LIFETIME" && semantic.key.scenario == "root-first")
    {
        let peers = behavior
            .peer_artifacts
            .iter()
            .map(|artifact| (artifact.role.as_str(), artifact.path.as_str()))
            .collect::<BTreeMap<_, _>>();
        let completion: Value = wire::decode(
            custody.bytes(
                peers
                    .get("orphan-completion")
                    .copied()
                    .ok_or("actual resource descendant completion product absent")?,
            )?,
        )?;
        let held = root_first_child.ok_or("root-first held child publication absent")?;
        let fields = [
            "format",
            "revision",
            "challenge",
            "pid",
            "birth",
            "original_parent_pid",
            "original_parent_birth",
            "reparented_pid",
        ];
        if completion.as_object().is_none_or(|object| {
            object.len() != fields.len() || object.keys().any(|key| !fields.contains(&key.as_str()))
        }) || completion["format"] != "memcordon.linux-orphan-completion"
            || completion["revision"] != 1
            || completion["challenge"] != hex::encode(custody.bytes(&semantic.challenge)?)
            || completion["pid"] != held["pid"]
            || completion["birth"] != held["birth"]
            || completion["original_parent_pid"].as_u64() != Some(local)
            || completion["original_parent_birth"].as_u64() != native.root_birth
            || completion["reparented_pid"].as_u64()
                != binding["namespace_init"]["namespace_pids"]
                    .as_array()
                    .and_then(|pids| pids.last())
                    .and_then(Value::as_u64)
            || completion["reparented_pid"] == completion["original_parent_pid"]
        {
            return Err(
                "resource descendant did not observe the held original parent's exit/reparenting"
                    .into(),
            );
        }
        let retired: Value = wire::decode(
            custody.bytes(
                peers
                    .get("native-retirement")
                    .copied()
                    .ok_or("held native descendant retirement receipt absent")?,
            )?,
        )?;
        if retired["format"] != "memcordon.linux-held-family-retirement"
            || retired["revision"] != 1
            || retired["run_id"] != native.run_id
            || retired["lease_id"].as_str() != native.lease_id.as_deref()
            || retired["attempt_id"].as_str() != native.attempt_id.as_deref()
            || retired["aggregate_empty"] != true
        {
            return Err("root-first independent cgroup retirement differs".into());
        }
        let members = retired["namespace_members"]
            .as_array()
            .ok_or("native child namespace map absent")?;
        if members.len() != 1
            || retired["descendants"]
                .as_array()
                .is_none_or(|descendants| descendants.len() != 1)
        {
            return Err("root-first native descendant cardinality differs".into());
        }
        let child = &members[0];
        if child["namespace_pid"] != completion["pid"] || child["birth"] != completion["birth"] {
            return Err(
                "resource child is not the independently mapped PID namespace member".into(),
            );
        }
        let identity = native
            .held_processes
            .iter()
            .find(|process| {
                Some(u64::from(process.pid)) == child["pid"].as_u64()
                    && Some(process.birth) == child["birth"].as_u64()
            })
            .ok_or("resource child is not a retained native identity")?;
        if identity.parent_pid != native.root_pid
            || identity.parent_birth != native.root_birth
            || !identity.retirement_observed
            || retired["descendants"][0]
                != serde_json::to_value(identity).map_err(|error| error.to_string())?
        {
            return Err(
                "resource descendant ancestry/retirement differs from its held native owner".into(),
            );
        }
        facts.operations.extend(
            [
                "held-descendant-identity",
                "descendant-natural-completion",
                "root-exited-before-held-descendant",
            ]
            .map(String::from),
        );
    }
    if build {
        let peers = behavior
            .peer_artifacts
            .iter()
            .map(|artifact| (artifact.role.as_str(), artifact.path.as_str()))
            .collect::<BTreeMap<_, _>>();
        if peers.len() != behavior.peer_artifacts.len() {
            return Err("Linux build raw peer role duplicated".into());
        }
        let raw = |role: &str| -> VerificationResult<Value> {
            wire::decode(
                custody.bytes(
                    peers
                        .get(role)
                        .copied()
                        .ok_or_else(|| format!("Linux build {role} raw artifact absent"))?,
                )?,
            )
        };
        let observation = |operation: &str| -> VerificationResult<&Value> {
            build_rows
                .get(operation)
                .ok_or_else(|| format!("actual Linux build {operation} observation absent"))
        };
        for (operation, role, field, expected) in [
            (
                "http-round-trip",
                "http",
                "request",
                b"GET /readiness HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
                    .as_slice(),
            ),
            (
                "http-round-trip",
                "http-response",
                "response",
                b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\nConnection: close\r\n\r\nreadiness"
                    .as_slice(),
            ),
            (
                "unix-path-round-trip",
                "unix-path",
                "bytes",
                b"path-unix-readiness".as_slice(),
            ),
            (
                "unix-abstract-round-trip",
                "unix-abstract",
                "bytes",
                b"abstract-unix-readiness".as_slice(),
            ),
            (
                "unix-stream-pair-round-trip",
                "unix-pair",
                "bytes",
                b"R".as_slice(),
            ),
        ] {
            let received: Vec<u8> = serde_json::from_value(observation(operation)?[field].clone())
                .map_err(|error| error.to_string())?;
            if received != expected
                || custody.bytes(
                    peers
                        .get(role)
                        .copied()
                        .ok_or("actual Joint received byte product absent")?,
                )? != received
            {
                return Err("Joint received native byte products differ from raw exchange".into());
            }
        }
        if observation("unix-path-round-trip")?["path"] != "/work/readiness.sock"
            || serde_json::from_value::<Vec<u8>>(
                observation("unix-abstract-round-trip")?["name"].clone(),
            )
            .map_err(|error| error.to_string())?
                != hex::encode(custody.bytes(&semantic.challenge)?).as_bytes()
        {
            return Err("Joint private Unix endpoint/challenge differs".into());
        }
        let http = observation("http-round-trip")?;
        let endpoint: std::net::SocketAddr = http["endpoint"]
            .as_str()
            .ok_or("Joint HTTP endpoint absent")?
            .parse()
            .map_err(|_| "Joint HTTP endpoint malformed")?;
        if !endpoint.is_ipv4()
            || !endpoint.ip().is_loopback()
            || endpoint.port() == 0
            || observation("bind-zero-and-competing-bind")?["endpoint"] != http["endpoint"]
            || observation("bind-zero-and-competing-bind")?["native_errno"] != 98
            || observation("bind-zero-and-competing-bind")?["listener_retained"] != true
        {
            return Err(
                "Joint native TCP listener/conflicting bind/HTTP association differs".into(),
            );
        }
        let compile = observation("offline-rust-compile-and-test")?;
        if compile["native_status"] != 0
            || compile["tcp_listener_still_bound"] != true
            || compile["output"] != "/work/offline-target"
            || observation("joint-unix-rights-held-through-build")?["owned_native_descriptors"]
                != 14
            || observation("joint-unix-rights-held-through-build")?["path"]
                != "/work/readiness.sock"
            || observation("joint-unix-rights-held-through-build")?["transferred_file"]
                != "/work/rights-input.bin"
            || observation("joint-descendant-tree-naturally-retired")?["tcp_listener_still_bound"]
                != true
        {
            return Err(
                "Joint lost live TCP/Unix/descriptor effects through actual offline build".into(),
            );
        }
        let input: FixtureInput = wire::decode(custody.bytes(&behavior.descriptor)?)?;
        let toolchain_path = peers
            .get("toolchain-inputs")
            .copied()
            .ok_or("measured Joint immutable compiler/linker/input images absent")?;
        if input.toolchain_identity.as_deref() != Some(custody.hash(toolchain_path)?) {
            return Err("Joint measured locked toolchain identity differs".into());
        }
        let manifest = raw("toolchain-inputs")?;
        if manifest.as_object().is_none_or(|object| {
            object.len() != 2 || !object.contains_key("runtime") || !object.contains_key("input")
        }) {
            return Err("Joint toolchain image schema differs".into());
        }
        let request = raw("build-request")?;
        if linux_image_reference(&manifest["runtime"], &native.target)? != request["runtime_image"]
            || linux_image_reference(&manifest["input"], &native.target)? != request["input_image"]
        {
            return Err(
                "Joint compiler/source image bytes are not the admitted immutable definitions"
                    .into(),
            );
        }
        for relative in [
            "Cargo.toml",
            "Cargo.lock",
            "rust-toolchain.toml",
            "src/main.rs",
            "tests/generated_child.rs",
        ] {
            let path = format!("owned-source/{relative}");
            let entries = manifest["input"]["entries"]
                .as_array()
                .ok_or("locked source entries absent")?;
            let entries = entries
                .iter()
                .filter(|entry| entry["path"] == path)
                .collect::<Vec<_>>();
            let role = format!("locked-source-{relative}");
            let bytes = custody.bytes(
                peers
                    .get(role.as_str())
                    .copied()
                    .ok_or("actual locked source bytes absent")?,
            )?;
            if entries.len() != 1
                || entries[0]["kind"] != "regular"
                || entries[0]["sha256"] != hex::encode(sha2::Sha256::digest(bytes))
                || entries[0]["size"] != bytes.len() as u64
            {
                return Err(
                    "actual compiled source/lock bytes differ from admitted input image".into(),
                );
            }
        }
        for path in ["toolchain/bin/cargo", "toolchain/bin/rustc", "usr/bin/cc"] {
            let entries = manifest["runtime"]["entries"]
                .as_array()
                .ok_or("toolchain entries absent")?;
            if entries
                .iter()
                .filter(|entry| {
                    entry["path"] == path
                        && entry["kind"] == "regular"
                        && entry["executable"] == true
                })
                .count()
                != 1
            {
                return Err("Joint locked compiler/linker native image entry absent".into());
            }
        }
        let created = raw("generated-created")?;
        let retired = raw("generated-retired")?;
        let compiler_live = raw("native-compiler-live")?;
        let generated_live = raw("native-generated-live")?;
        for (barrier, path) in [
            (&compiler_live, "bin/owned-readiness"),
            (&generated_live, "toolchain/bin/cargo"),
        ] {
            let members = barrier["members"]
                .as_array()
                .ok_or("actual native compiler image observation absent")?;
            let compiler = members
                .iter()
                .filter(|member| {
                    member["native"]["namespace_pids"]
                        .as_array()
                        .and_then(|pids| pids.last())
                        == Some(&created["compiler_pid"])
                        && member["native"]["birth"] == created["compiler_birth"]
                })
                .collect::<Vec<_>>();
            let entries = manifest["runtime"]["entries"]
                .as_array()
                .expect("validated image entries");
            let image = entries
                .iter()
                .find(|entry| entry["path"] == path && entry["kind"] == "regular")
                .ok_or("approved native compiler image absent")?;
            if compiler.len() != 1
                || compiler[0]["executable"]["sha256"] != image["sha256"]
                || compiler[0]["executable"]["length"] != image["size"]
            {
                return Err(
                    "actual held compiler executable differs from approved immutable runtime bytes"
                        .into(),
                );
            }
        }
        if observation("joint-generated-child-held")?["created"] != created {
            return Err(
                "generated fixture readiness differs from actual exported creation receipt".into(),
            );
        }
        validate_linux_generated_lifecycle(
            &created,
            &retired,
            &compiler_live,
            &generated_live,
            &binding["target"],
            &native.held_processes,
            (
                native.root_pid.ok_or("held Joint root absent")?,
                native.root_birth.ok_or("held Joint root birth absent")?,
            ),
            native
                .attempt_id
                .as_deref()
                .ok_or("Joint admission absent")?,
            custody.bytes(&semantic.challenge)?,
            &native.target,
            custody.bytes(
                peers
                    .get("generated-executable")
                    .copied()
                    .ok_or("actual generated native ELF absent")?,
            )?,
        )?;
        let product = observation("generated-executable-binary-product")?;
        let expected: Vec<u8> = (u8::MIN..=u8::MAX).collect();
        if product["path"] != "/work/generated-readiness-artifact.bin"
            || product["inode"].as_u64().is_none_or(|inode| inode == 0)
            || serde_json::from_value::<Vec<u8>>(product["bytes"].clone())
                .map_err(|error| error.to_string())?
                != expected
        {
            return Err("generated executable actual all-byte output differs".into());
        }
        facts.operations.extend(
            [
                "http-exchange",
                "unix-path-exchange",
                "unix-abstract-exchange",
                "unix-stream-pair",
                "locked-rust-compile",
                "compiled-tests",
                "generated-executable",
            ]
            .map(String::from),
        );
    }
    Ok(facts)
}
