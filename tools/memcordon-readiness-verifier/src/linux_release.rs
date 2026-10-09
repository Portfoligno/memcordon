//! The leased callback barrier does not establish private-root execution.
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxReleaseReceipt {
    pub format: String,
    pub revision: u32,
    pub run_id: String,
    pub recipe_id: String,
    pub native_target: String,
    pub test_name: String,
    pub executable_sha256: String,
    pub challenge_sha256: String,
    pub fixture: String,
    pub fixture_sha256: String,
    pub scope: String,
    pub observations: Vec<LinuxReleaseObservation>,
    pub helper_retirement: Vec<LinuxReleaseWait>,
}

impl LinuxReleaseReceipt {
    pub fn artifact_paths(&self) -> Vec<&str> {
        let mut paths = vec![self.fixture.as_str()];
        for row in &self.observations {
            paths.extend([
                row.effective_invocation.as_str(),
                row.journal_before.as_str(),
                row.journal_after.as_str(),
                row.reference.as_str(),
            ]);
        }
        paths
    }
}

/// Full raw receipt joins. Original-job native harness/input/capture custody
/// and selected resource acquisition remain mandatory in the enclosing gate.
pub fn validate_linux_release_receipt(
    receipt: &LinuxReleaseReceipt,
    run_id: &str,
    recipe_id: &str,
    target: &str,
    executable_sha256: &str,
    challenge: &[u8],
    worker: (u32, u64),
    account: (u32, u32),
    mut read: impl FnMut(&str) -> Result<Vec<u8>, String>,
) -> Result<(), String> {
    crate::header(
        &receipt.format,
        receipt.revision,
        "memcordon.linux-leased-release-component",
    )?;
    if receipt.run_id != run_id
        || receipt.recipe_id != recipe_id
        || receipt.native_target != target
        || receipt.executable_sha256 != executable_sha256
        || receipt.challenge_sha256 != crate::sha256(challenge)
        || receipt.test_name
            != "native_mixed_release::native_leased_release_emit_actual_component_receipt"
        || !target.ends_with("linux-gnu")
    {
        return Err("leased release original native source/input association differs".into());
    }
    let fixture_bytes = read(&receipt.fixture)?;
    if fixture_bytes.len() > 16 * 1024 * 1024
        || crate::sha256(&fixture_bytes) != receipt.fixture_sha256
    {
        return Err("leased release protected fixture bytes differ".into());
    }
    let fixture: Value = crate::wire::decode(&fixture_bytes)?;
    let (prefix, leaf) = receipt
        .fixture
        .rsplit_once('/')
        .ok_or("leased fixture original namespace absent")?;
    if leaf != "release-fixture.json" {
        return Err("leased fixture substitutes a different retained descriptor".into());
    }
    validate_linux_release_policy(receipt, &fixture, challenge)?;
    let identities = fixture["registry"]["execution_identities"]
        .as_array()
        .ok_or("leased exclusive identities absent")?;
    let selected = identities
        .iter()
        .filter(|identity| {
            identity["identity_id"] == fixture["contract"]["execution_identity"]["identity"]["id"]
        })
        .collect::<Vec<_>>();
    if selected.len() != 1
        || selected[0]["enabled"] != true
        || selected[0]["uid"] != account.0
        || selected[0]["gid"] != account.1
        || account.0 == 0
        || account.1 == 0
    {
        return Err("leased account differs from acquired exclusive identity".into());
    }
    let effective = linux_release_effective_invocation(&fixture, target)?;
    let caller = &receipt.helper_retirement[0];
    if receipt
        .helper_retirement
        .iter()
        .any(|helper| helper.pid == worker.0)
    {
        return Err("leased helper substitutes original harness identity".into());
    }
    let mut paths = std::collections::BTreeSet::new();
    for path in receipt.artifact_paths() {
        if path.is_empty()
            || path.starts_with('/')
            || path.contains(['\\', ':'])
            || path
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || !paths.insert(path)
        {
            return Err("leased raw references are aliased or escape original bundle".into());
        }
    }
    for (index, row) in receipt.observations.iter().enumerate() {
        let suffix = if index == 0 { "stale" } else { "current" };
        if row.effective_invocation != format!("{prefix}/{suffix}-effective-invocation.bin")
            || row.journal_before != format!("{prefix}/{suffix}-journal-before.bin")
            || row.journal_after != format!("{prefix}/{suffix}-journal-after.bin")
            || row.reference != format!("{prefix}/{suffix}-reference.json")
        {
            return Err("leased raw references differ from original recipe namespace".into());
        }
        let actual = read(&row.effective_invocation)?;
        if actual != effective {
            return Err(
                "leased native effective invocation differs from immutable image recipe".into(),
            );
        }
        let mut bound = actual;
        bound.extend_from_slice(
            &hex::decode(
                row.metadata["request_sha256"]
                    .as_str()
                    .ok_or("leased request digest absent")?,
            )
            .map_err(|error| error.to_string())?,
        );
        if row.metadata["invocation_sha256"] != crate::sha256(&bound) {
            return Err("leased effective invocation/request binding differs".into());
        }
        let before = read(&row.journal_before)?;
        let after = read(&row.journal_after)?;
        let reference = read(&row.reference)?;
        if reference.len() > 1024 * 1024 {
            return Err("leased reference exceeds bounded native metadata".into());
        }
        validate_linux_release_ownership(
            row, &before, &after, &reference, worker, caller, account.0,
        )?;
    }
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxReleaseObservation {
    pub scenario: String,
    pub metadata: Value,
    pub effective_invocation: String,
    pub journal_before: String,
    pub journal_after: String,
    pub reference: String,
    pub reference_native_before: LinuxReleaseReference,
    pub reference_native_after: LinuxReleaseReference,
    pub activation_before: Value,
    pub activation_after: Value,
    pub target_pid: u32,
    pub target_birth: u64,
    pub target_retirement: LinuxReleaseWait,
    pub gate: LinuxReleaseGate,
    pub private_root_materialized: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxReleaseGate {
    pub refusal: Option<String>,
    pub received: Vec<u8>,
    pub callbacks: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LinuxReleaseWait {
    pub pid: u32,
    pub birth: u64,
    pub raw_wait_status: i32,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub pidfd_retirement_observed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinuxReleaseReference {
    pub device: u64,
    pub inode: u64,
    pub length: u64,
    pub links: u64,
    pub uid: u32,
    pub mode: u32,
    pub named_absent: bool,
    pub account_uid: u32,
    pub retired: bool,
}

/// Joins the allocated ownership journal and reference to the actual held
/// harness/caller. It deliberately establishes no private-root execution.
pub fn validate_linux_release_ownership(
    observation: &LinuxReleaseObservation,
    before: &[u8],
    after: &[u8],
    reference: &[u8],
    worker: (u32, u64),
    caller: &LinuxReleaseWait,
    account_uid: u32,
) -> Result<(), String> {
    if worker.0 == 0
        || worker.1 == 0
        || observation.private_root_materialized
        || before != after
        || before.is_empty()
        || before.len() > 1024 * 1024
    {
        return Err("leased release journal/native ownership differs".into());
    }
    let metadata = &observation.metadata;
    let metadata_fields = [
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
    ];
    closed_fields(metadata, &metadata_fields)?;
    let attempt = metadata["attempt_id"]
        .as_str()
        .ok_or("leased attempt absent")?;
    if attempt.len() != 32
        || !attempt
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || metadata["format"] != "memcordon.private-admission-metadata"
        || metadata["revision"] != 2
        || metadata["caller_uid"] != 65534
    {
        return Err("leased release original admission metadata differs".into());
    }
    for field in ["request_sha256", "invocation_sha256", "registry_digest"] {
        crate::digest(
            metadata[field]
                .as_str()
                .ok_or("leased metadata digest absent")?,
        )?;
    }
    let retained_reference: Value = crate::wire::decode(reference)?;
    if retained_reference != *metadata {
        return Err("leased release reference substitutes admission metadata".into());
    }
    validate_linux_release_reference(
        &observation.reference_native_before,
        &observation.reference_native_after,
        account_uid,
        reference.len() as u64,
    )?;
    let text = std::str::from_utf8(before).map_err(|error| error.to_string())?;
    let (body, checksum) = text
        .rsplit_once("digest=")
        .ok_or("leased journal checksum absent")?;
    if checksum != format!("{}\n", crate::sha256(body.as_bytes())) {
        return Err("leased journal checksum differs".into());
    }
    let mut lines = body.lines();
    if lines.next() != Some("format=memcordon.private-native-journal")
        || lines.next() != Some("revision=1")
        || lines.next() != Some(format!("cgroup={attempt}").as_str())
    {
        return Err("leased journal native envelope differs".into());
    }
    let payload = lines
        .next()
        .and_then(|line| line.strip_prefix("payload="))
        .ok_or("leased journal payload absent")?;
    if lines.next().is_some() {
        return Err("leased journal envelope has extra fields".into());
    }
    let record: Value = crate::wire::decode(payload.as_bytes())?;
    closed_fields(
        &record,
        &[
            "attempt_id",
            "boot_identity",
            "frontend",
            "caller_envelope_digest",
            "admission_metadata",
            "phase",
            "release_knowledge",
            "binding",
            "guardian",
            "namespace_init",
            "target",
            "network_namespace_inode",
            "checkpoint",
            "checkpoint_digest",
            "gated_facts",
            "cleanup_error",
            "mixed_admission_metadata",
            "mixed_worker",
        ],
    )?;
    closed_fields(&record["frontend"], &["pid", "start_time"])?;
    closed_fields(&record["mixed_worker"], &["pid", "start_time"])?;
    crate::digest(
        record["caller_envelope_digest"]
            .as_str()
            .ok_or("leased caller envelope digest absent")?,
    )?;
    if record["attempt_id"] != attempt
        || record["mixed_admission_metadata"] != *metadata
        || record["frontend"]["pid"] != caller.pid
        || record["frontend"]["start_time"] != caller.birth
        || record["mixed_worker"]["pid"] != worker.0
        || record["mixed_worker"]["start_time"] != worker.1
        || record["boot_identity"]
            .as_str()
            .is_none_or(|boot| boot.is_empty() || boot.len() > 128)
        || record["phase"] != "allocated"
        || record["release_knowledge"] != "not-released"
        || [
            "admission_metadata",
            "binding",
            "guardian",
            "namespace_init",
            "target",
            "network_namespace_inode",
            "checkpoint",
            "checkpoint_digest",
            "gated_facts",
            "cleanup_error",
        ]
        .iter()
        .any(|field| !record[*field].is_null())
    {
        return Err(
            "leased journal invents native target/release or changes original ownership".into(),
        );
    }
    Ok(())
}

fn closed_fields(value: &Value, fields: &[&str]) -> Result<(), String> {
    if value.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|field| !fields.contains(&field.as_str()))
    }) {
        return Err("leased release raw object has missing or unknown fields".into());
    }
    Ok(())
}

/// Check both original native lease snapshots against the retained setup.
/// Executable reconstruction and custody are required separately by routing.
pub fn validate_linux_release_policy(
    receipt: &LinuxReleaseReceipt,
    fixture: &Value,
    challenge: &[u8],
) -> Result<(), String> {
    use sha2::{Digest, Sha256};
    closed_fields(fixture, &["contract", "registry"])?;
    if challenge.len() != 32
        || challenge.iter().all(|byte| *byte == 0)
        || receipt.observations.len() != 2
        || receipt.helper_retirement.len() != 3
        || receipt.scope != "inner-leased-callback-no-private-root"
    {
        return Err("leased release finite source scope differs".into());
    }
    let digest =
        crate::linux_registry::linux_registry_digest(&fixture["registry"], &receipt.native_target)?;
    let mut contract = fixture["contract"].clone();
    let mut identities = std::collections::BTreeSet::new();
    for helper in &receipt.helper_retirement {
        if helper.pid == 0
            || helper.birth == 0
            || !helper.pidfd_retirement_observed
            || !identities.insert((helper.pid, helper.birth))
        {
            return Err("leased helper native identities are missing or duplicated".into());
        }
        let native = match (helper.exit_code, helper.signal) {
            (Some(0), None) => 0,
            (None, Some(9)) => 9,
            _ => return Err("leased helper native termination differs".into()),
        };
        if helper.raw_wait_status != native {
            return Err("leased helper raw wait differs".into());
        }
    }
    if receipt.helper_retirement[0].signal != Some(9) {
        return Err("leased original caller was not natively retired".into());
    }
    for (index, observation) in receipt.observations.iter().enumerate() {
        let stale = index == 0;
        let scenario = if stale {
            "stale-epoch-refused"
        } else {
            "current-epoch-released"
        };
        if observation.scenario != scenario
            || observation.target_retirement != receipt.helper_retirement[index + 1]
            || observation.private_root_materialized
        {
            return Err("leased observation changes scenario or held target".into());
        }
        validate_linux_release_gate(
            scenario,
            &observation.gate,
            &observation.target_retirement,
            observation.target_pid,
            observation.target_birth,
        )?;
        let before = &observation.activation_before;
        let after = &observation.activation_after;
        if crate::linux_policy::activation_registry(before)? != &fixture["registry"]
            || crate::linux_policy::activation_registry(after)? != &fixture["registry"]
            || before["registry_digest"] != digest
            || after["registry_digest"] != digest
            || before["revoked_admissions"] != serde_json::json!([])
            || after["revoked_admissions"] != serde_json::json!([])
            || before["epoch"] != contract["expected_epoch"]
        {
            return Err("leased snapshots differ from original activated registry".into());
        }
        if stale {
            let old = before["epoch"]["revision"]
                .as_u64()
                .ok_or("leased old epoch revision absent")?;
            let new = after["epoch"]["revision"]
                .as_u64()
                .ok_or("leased new epoch revision absent")?;
            if before["epoch"]["service_instance"] != after["epoch"]["service_instance"]
                || new <= old
            {
                return Err("leased stale rejection lacks actual later epoch".into());
            }
        } else if before != after {
            return Err("leased positive changes its held policy lease".into());
        }
        let mut attempt = Sha256::new();
        attempt.update(challenge);
        attempt.update([u8::from(stale)]);
        let expected_attempt = hex::encode(&attempt.finalize()[..16]);
        let metadata = &observation.metadata;
        let contract_digest = crate::wire::v3_request_digest(&contract)?;
        if metadata["attempt_id"] != expected_attempt
            || metadata["request"] != contract
            || metadata["request_sha256"] != contract_digest
            || metadata["registry_digest"] != digest
            || metadata["epoch"] != before["epoch"]
            || metadata["profile_id"] != contract["authorized_profile"]
            || metadata["admission_nonce"].as_array().is_none_or(|nonce| {
                nonce.len() != 16
                    || nonce
                        .iter()
                        .any(|byte| byte.as_u64().is_none_or(|byte| byte > 255))
                    || nonce.iter().all(|byte| byte == 0)
            })
        {
            return Err(
                "leased actual admission does not bind setup request/epoch/challenge".into(),
            );
        }
        contract["expected_epoch"] = after["epoch"].clone();
    }
    Ok(())
}

/// Independently reconstruct the effective native request of the fixed inner
/// release recipe from its immutable image catalogue and entrypoint selector.
pub fn linux_release_effective_invocation(
    fixture: &Value,
    target: &str,
) -> Result<Vec<u8>, String> {
    let contract = &fixture["contract"];
    let images = fixture["registry"]["images"]
        .as_array()
        .ok_or("leased image catalogue absent")?;
    let select = |field: &str| -> Result<&Value, String> {
        let matching = images
            .iter()
            .filter(|image| image["image_id"] == contract[field]["id"])
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            return Err("leased image selection is not unique".into());
        }
        let image = matching[0];
        if crate::linux_build::linux_image_reference(image, target)? != contract[field] {
            return Err("leased immutable image reference differs".into());
        }
        Ok(image)
    };
    let runtime = select("runtime_image")?;
    let input = select("input_image")?;
    let entries = runtime["entrypoints"]
        .as_array()
        .ok_or("leased entrypoints absent")?;
    let matching = entries
        .iter()
        .filter(|entry| entry["id"] == contract["launch"]["entrypoint"])
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err("leased native entrypoint selection is not unique".into());
    }
    let program = format!(
        "/{}",
        matching[0]["path"]
            .as_str()
            .ok_or("leased native program absent")?
    );
    let mut environment = std::collections::BTreeMap::<String, String>::new();
    let mut directories = Vec::<String>::new();
    for image in [runtime, input] {
        for variable in image["startup_environment"]
            .as_array()
            .ok_or("leased startup environment absent")?
        {
            let name = variable["name"]
                .as_str()
                .ok_or("leased variable name absent")?;
            let value = variable["value"]
                .as_str()
                .ok_or("leased variable value absent")?;
            if environment
                .insert(name.to_owned(), value.to_owned())
                .is_some()
            {
                return Err("leased image variables overlap".into());
            }
        }
        for directory in image["library_directories"]
            .as_array()
            .ok_or("leased library directories absent")?
        {
            let directory = directory
                .as_str()
                .ok_or("leased library directory malformed")?
                .to_owned();
            if !directories.contains(&directory) {
                directories.push(directory);
            }
        }
    }
    if !directories.is_empty() {
        environment.insert(
            "LD_LIBRARY_PATH".into(),
            directories
                .iter()
                .map(|path| format!("/{path}"))
                .collect::<Vec<_>>()
                .join(":"),
        );
    }
    fn count(bytes: &mut Vec<u8>, value: usize) -> Result<(), String> {
        bytes.extend_from_slice(
            &u32::try_from(value)
                .map_err(|_| "leased count exceeds native u32")?
                .to_be_bytes(),
        );
        Ok(())
    }
    fn text(bytes: &mut Vec<u8>, value: &str) -> Result<(), String> {
        count(bytes, value.len())?;
        bytes.extend_from_slice(value.as_bytes());
        Ok(())
    }
    let mut bytes = 3u16.to_be_bytes().to_vec();
    bytes.extend_from_slice(&0u64.to_be_bytes());
    text(&mut bytes, &program)?;
    count(&mut bytes, 0)?;
    count(&mut bytes, environment.len())?;
    for (name, value) in environment {
        text(&mut bytes, &name)?;
        text(&mut bytes, &value)?;
    }
    bytes.push(1);
    bytes.extend_from_slice(&(1024u64 * 1024 * 1024).to_be_bytes());
    bytes.push(1);
    bytes.extend_from_slice(&0u64.to_be_bytes());
    bytes.extend_from_slice(&[0, 1, 2]);
    for scalar in [10u64, 100, 100, 100] {
        bytes.extend_from_slice(&scalar.to_be_bytes());
    }
    count(&mut bytes, 5)?;
    bytes.extend_from_slice(&[1, 2, 3, 4, 5, 0]);
    Ok(bytes)
}

/// Decode unchanged acquisition and native account creation readbacks. This is
/// source association, not a fresh account-absence observation.
pub fn validate_linux_component_fixture_acquisition(
    checkpoint: &Value,
    intent: &Value,
    passwd: &[u8],
    group: &[u8],
    run_id: &str,
    source_commit: &str,
    source_tree_sha256: &str,
    version: &str,
    target: &str,
) -> Result<(u32, u32), String> {
    closed_fields(
        checkpoint,
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
    let identity = serde_json::json!({"run_id":run_id,"source_commit":source_commit,
        "source_tree_sha256":source_tree_sha256,"version":version});
    let cell = serde_json::json!({"target":target,"channel":"candidate-native"});
    if checkpoint["format"] != "memcordon.owned-readiness-resources"
        || checkpoint["revision"] != 1
        || checkpoint["identity"] != identity
        || checkpoint["cell"] != cell
        || checkpoint["device"].as_u64().is_none_or(|value| value == 0)
        || checkpoint["inode"].as_u64().is_none_or(|value| value == 0)
        || checkpoint["admin_root"].as_str().is_none_or(|root| {
            !root.starts_with("/var/lib/memcordon-native-readiness/")
                || root.split('/').any(|part| part == "." || part == "..")
        })
        || !checkpoint["images"].is_object()
    {
        return Err(
            "component fixture acquisition differs from original source/cell/native owner".into(),
        );
    }
    let account = &checkpoint["account"];
    closed_fields(
        &checkpoint["images"],
        &[
            "runtime",
            "input",
            "runtime_definition",
            "input_definition",
            "runtime_source",
            "input_source",
            "fixture_sha256",
            "native_linker",
            "import_receipts",
        ],
    )?;
    if !checkpoint["images"]["runtime"].is_object() || !checkpoint["images"]["input"].is_object() {
        return Err("component acquired image definitions absent".into());
    }
    closed_fields(
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
    let native_u32 = |field: &str| {
        account[field]
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .filter(|value| *value > 0)
            .ok_or_else(|| format!("component acquired account {field} invalid"))
    };
    let uid = native_u32("uid")?;
    let gid = native_u32("gid")?;
    let name = account["name"]
        .as_str()
        .filter(|name| name.starts_with("mc-ready-") && name.len() <= 64)
        .ok_or("component acquired account name invalid")?;
    #[derive(Serialize)]
    struct OriginalIdentity<'a> {
        run_id: &'a str,
        source_commit: &'a str,
        source_tree_sha256: &'a str,
        version: &'a str,
    }
    let original = OriginalIdentity {
        run_id,
        source_commit,
        source_tree_sha256,
        version,
    };
    let original_cell = crate::ProductKey {
        target: target.to_owned(),
        channel: "candidate-native".into(),
    };
    let discriminator = crate::sha256(
        &serde_json::to_vec(&(original, original_cell)).map_err(|error| error.to_string())?,
    );
    let raw = hex::decode(discriminator).map_err(|error| error.to_string())?;
    let number = u64::from_le_bytes(
        raw[..8]
            .try_into()
            .map_err(|_| "component account discriminator width differs")?,
    );
    if name != format!("mc-ready-{number:x}") {
        return Err(
            "component acquired account name differs from original source/cell discriminator"
                .into(),
        );
    }
    let intent_path = account["intent"]
        .as_str()
        .ok_or("component account original intent path absent")?;
    let (parent, leaf) = intent_path
        .rsplit_once('/')
        .ok_or("component account original output parent absent")?;
    if leaf != "exclusive-account-intent.json"
        || parent
            != format!(
                "{}/native-package-evidence/resources",
                checkpoint["admin_root"]
                    .as_str()
                    .ok_or("component native admin root absent")?
            )
        || account["native_readback"] != format!("{parent}/exclusive-account-getent.bin")
        || account["group_readback"] != format!("{parent}/exclusive-group-getent.bin")
    {
        return Err("component account native creation paths redirected".into());
    }
    closed_fields(
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
    if intent["format"] != "memcordon.owned-readiness-account-intent"
        || intent["revision"] != 1
        || intent["run_id"] != run_id
        || intent["cell"] != cell
        || intent["account_name"] != name
        || intent["native_absence_verified"] != true
        || intent["creation_attempted"] != true
    {
        return Err("component account intent differs from original acquisition".into());
    }
    if passwd.len() > 4096 || group.len() > 4096 || !passwd.ends_with(b"\n") {
        return Err("component native account creation readback bound/termination differs".into());
    }
    let text = std::str::from_utf8(passwd).map_err(|error| error.to_string())?;
    if text.lines().count() != 1 {
        return Err("component passwd readback is not one original identity".into());
    }
    let fields = text.trim_end_matches('\n').split(':').collect::<Vec<_>>();
    if fields.len() != 7
        || fields[0] != name
        || fields[2] != uid.to_string()
        || fields[3] != gid.to_string()
        || fields[6] != "/usr/sbin/nologin"
        || group != format!("{name}:x:{gid}:\n").as_bytes()
    {
        return Err("component native account/group creation identity differs".into());
    }
    Ok((uid, gid))
}

pub fn validate_linux_release_reference(
    before: &LinuxReleaseReference,
    after: &LinuxReleaseReference,
    account_uid: u32,
    reference_length: u64,
) -> Result<(), String> {
    if account_uid == 0
        || before.device == 0
        || before.inode == 0
        || before.length != reference_length
        || reference_length == 0
        || before.links != 1
        || before.uid != 0
        || before.mode & 0o170000 != 0o100000
        || before.mode & 0o7777 != 0o600
        || before.named_absent
        || before.retired
        || before.account_uid != account_uid
        || after.device != before.device
        || after.inode != before.inode
        || after.length != before.length
        || after.uid != before.uid
        || after.mode != before.mode
        || after.account_uid != account_uid
        || after.links != 0
        || !after.named_absent
        || !after.retired
    {
        return Err("leased release retained reference/native retirement differs".into());
    }
    Ok(())
}

/// Checks the actual callback and native wait observations. The caller must
/// separately join the policy lease, held executable, journal and reference.
pub fn validate_linux_release_gate(
    scenario: &str,
    gate: &LinuxReleaseGate,
    wait: &LinuxReleaseWait,
    pid: u32,
    birth: u64,
) -> Result<(), String> {
    if pid == 0
        || birth == 0
        || wait.pid != pid
        || wait.birth != birth
        || !wait.pidfd_retirement_observed
    {
        return Err("leased release target native identity/retirement differs".into());
    }
    let native_status = match (wait.exit_code, wait.signal) {
        (Some(code), None) if (0..=255).contains(&code) => code << 8,
        (None, Some(signal)) if (1..=127).contains(&signal) => signal,
        _ => return Err("leased release native wait is not an exit or signal".into()),
    };
    if wait.raw_wait_status != native_status {
        return Err("leased release raw native wait differs".into());
    }
    match scenario {
        "stale-epoch-refused"
            if gate.refusal.as_deref() == Some("mixed epoch/grant changed before release")
                && gate.received.is_empty()
                && gate.callbacks == 0
                && wait.signal == Some(9) =>
        {
            Ok(())
        }
        "current-epoch-released"
            if gate.refusal.is_none()
                && gate.received == [165]
                && gate.callbacks == 1
                && (wait.exit_code == Some(0) || wait.signal == Some(9)) =>
        {
            Ok(())
        }
        _ => Err("leased release actual callback/gate observation differs".into()),
    }
}
