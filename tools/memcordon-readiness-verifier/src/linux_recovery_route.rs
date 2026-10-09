//! Recovery components retain their own raw native protocol. They never pass
//! through a synthetic successful target observation or a Rust test counter.
use crate::{custody::Custody, linux_recovery::*, wire, *};
use serde_json::Value;

fn closed(value: &Value, fields: &[&str]) -> VerificationResult<()> {
    if value.as_object().is_none_or(|object| {
        object.len() != fields.len() || object.keys().any(|field| !fields.contains(&field.as_str()))
    }) {
        return Err("native recovery raw object shape differs".into());
    }
    Ok(())
}
fn number(value: &Value, field: &str) -> VerificationResult<u64> {
    value[field]
        .as_u64()
        .ok_or_else(|| format!("native recovery integer absent: {field}"))
}
fn text<'a>(value: &'a Value, field: &str) -> VerificationResult<&'a str> {
    value[field]
        .as_str()
        .ok_or_else(|| format!("native recovery text absent: {field}"))
}

pub(crate) fn validate(
    index: &EvidenceIndex,
    record: &CaseRecord,
    e: &LinuxNativeRecoveryCaseEvidence,
    builds: &BTreeMap<String, &ComponentBuild>,
    custody: &Custody,
) -> VerificationResult<()> {
    header(
        &e.format,
        e.revision,
        "memcordon.consumer-readiness.linux-native-recovery",
    )?;
    let origin = producer_origin(index, &record.key.target, None)?;
    if e.key != record.key
        || e.run_id != origin.run_id
        || e.source_commit != index.source_commit
        || e.source_tree_sha256 != index.source_tree_sha256
        || e.key.channel.is_some()
        || e.key.family != "L-LIFE-04"
        || !e.key.target.ends_with("linux-gnu")
    {
        return Err("native recovery row/source/channel association differs".into());
    }
    let build = builds
        .values()
        .find(|build| build.target == e.key.target && build.recipe_id == e.component_recipe_id)
        .ok_or("native recovery original component build absent")?;
    if !build.instrumented
        || build.executable != e.executable
        || build.source_commit != index.source_commit
        || build.source_tree_sha256 != index.source_tree_sha256
        || custody.hash(&e.executable)? != e.executable_sha256
        || custody.hash(&e.source_artifact)? != e.source_artifact_sha256
        || e.source_artifact_sha256 != index.source_tree_sha256
    {
        return Err("native recovery selected original source/image differs".into());
    }
    for path in e.artifact_paths() {
        custody.bytes(path)?;
    }
    let (
        input_path,
        boundary_path,
        ownership_path,
        invocation_path,
        capture_path,
        process_path,
        owner_path,
        recovered_path,
        acquired,
        recipe,
        test,
    ) = match &e.recovery {
        LinuxRecoveryComponentEvidence::AccountRetirementCrash {
            input,
            boundary,
            ownership,
            recovery_invocation,
            recovery_capture,
            recovery_process,
            package_owner,
            recovered_ownership,
            fixture_acquisition,
            ..
        } if e.key.scenario == "crash-before-account-retirement" => (
            input,
            boundary,
            ownership,
            recovery_invocation,
            recovery_capture,
            recovery_process,
            package_owner,
            recovered_ownership,
            fixture_acquisition,
            "account-retirement",
            "native_mixed_recovery::native_account_retirement_boundary_emit_actual_receipt",
        ),
        LinuxRecoveryComponentEvidence::LostTerminalResponse {
            input,
            boundary,
            ownership,
            recovery_invocation,
            recovery_capture,
            recovery_process,
            package_owner,
            recovered_ownership,
            fixture_acquisition,
            ..
        } if e.key.scenario == "lost-terminal-response" => (
            input,
            boundary,
            ownership,
            recovery_invocation,
            recovery_capture,
            recovery_process,
            package_owner,
            recovered_ownership,
            fixture_acquisition,
            "lost-terminal",
            "native_mixed_recovery::native_lost_terminal_response_emit_actual_receipt",
        ),
        _ => return Err("native recovery finite recipe/key differs".into()),
    };
    let base = format!("{}/candidate-native/components", e.key.target);
    let prefix = format!("{base}/{recipe}");
    for (path, leaf) in [
        (input_path.as_str(), "native-input.json"),
        (boundary_path.as_str(), "account-boundary.json"),
        (ownership_path.as_str(), "account-ownership.json"),
        (invocation_path.as_str(), "native-recovery-invocation.json"),
        (capture_path.as_str(), "native-recovery-capture.json"),
        (process_path.as_str(), "native-recovery-process.json"),
        (recovered_path.as_str(), "recovered-ownership.json"),
        (e.invocation.as_str(), "native-spawn-intent.json"),
        (e.native_preinput.as_str(), "native-pre-input.json"),
        (e.native_retirement.as_str(), "native-retirement.json"),
        (e.stdout.as_str(), "stdout.bin"),
        (e.stderr.as_str(), "stderr.bin"),
    ] {
        if path != format!("{prefix}/{leaf}") {
            return Err("native recovery redirects original raw recipe leaf".into());
        }
    }
    if owner_path != &format!("{base}/native-fixture/native-package-owner.json")
        || acquired.checkpoint != format!("{base}/native-fixture/owned-resources-acquired.json")
        || acquired.account_intent != format!("{base}/native-fixture/exclusive-account-intent.json")
        || acquired.account_readback
            != format!("{base}/native-fixture/exclusive-account-getent.bin")
        || acquired.group_readback != format!("{base}/native-fixture/exclusive-group-getent.bin")
    {
        return Err("native recovery acquired account/package owner scope differs".into());
    }
    let json = |path: &str| -> VerificationResult<Value> { wire::decode(custody.bytes(path)?) };
    let input = json(input_path)?;
    let boundary = json(boundary_path)?;
    closed(
        &input,
        &[
            "run_id",
            "recipe_id",
            "native_target",
            "artifact_root",
            "artifact_prefix",
            "challenge",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
            "fixture_path",
            "fixture_sha256",
        ],
    )?;
    closed(
        &boundary,
        &[
            "format",
            "revision",
            "run_id",
            "recipe_id",
            "native_target",
            "test_name",
            "worker",
            "challenge_sha256",
            "fixture",
            "fixture_sha256",
            "current_contract",
            "actual_activation",
            "journal",
            "reference",
            "native",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
    )?;
    let challenge: Vec<u8> =
        serde_json::from_value(input["challenge"].clone()).map_err(|error| error.to_string())?;
    let work = number(&input, "work_deadline_unix_millis")?;
    let cleanup = number(&input, "cleanup_deadline_unix_millis")?;
    if challenge.len() != 32
        || challenge.iter().all(|byte| *byte == 0)
        || work == 0
        || cleanup <= work
        || input["artifact_prefix"] != prefix
        || boundary["format"] != "memcordon.linux-pre-account-native-boundary"
        || boundary["revision"] != 1
        || boundary["test_name"] != test
        || boundary["challenge_sha256"] != sha256(&challenge)
    {
        return Err("native recovery original boundary/challenge differs".into());
    }
    for raw in [&input, &boundary] {
        if raw["run_id"] != e.run_id
            || raw["recipe_id"] != e.component_recipe_id
            || raw["native_target"] != e.key.target
            || raw["work_deadline_unix_millis"] != work
            || raw["cleanup_deadline_unix_millis"] != cleanup
        {
            return Err("native recovery original input/source/deadline differs".into());
        }
    }
    let spawn = json(&e.invocation)?;
    let before = json(&e.native_preinput)?;
    let retired = json(&e.native_retirement)?;
    closed(
        &spawn,
        &[
            "format",
            "revision",
            "program_bytes",
            "argv_bytes",
            "environment_cleared",
            "image_sha256",
            "test_name",
        ],
    )?;
    let program: Vec<u8> = serde_json::from_value(spawn["program_bytes"].clone())
        .map_err(|error| error.to_string())?;
    if !program.starts_with(b"/") || program.len() > 131072 || program.contains(&0) {
        return Err(
            "native recovery selected executable path is not absolute bounded native bytes".into(),
        );
    }
    closed(
        &before,
        &[
            "process_id",
            "birth",
            "image_sha256",
            "held_before_input_delivery",
            "test_name",
        ],
    )?;
    closed(
        &retired,
        &[
            "format",
            "revision",
            "process_id",
            "birth",
            "image_sha256",
            "held_before_input_delivery",
            "retirement_observed",
            "same_image_helpers_absent",
        ],
    )?;
    let worker = LinuxRecoveryProcess {
        pid: number(&before, "process_id")?
            .try_into()
            .map_err(|_| "native recovery worker PID overflow")?,
        birth: number(&before, "birth")?,
    };
    if worker.pid == 0
        || worker.pid > i32::MAX as u32
        || worker.birth == 0
        || before["held_before_input_delivery"] != true
        || before["test_name"] != test
        || spawn["test_name"] != test
        || spawn["environment_cleared"] != true
        || spawn["format"] != "memcordon.linux-native-test-invocation"
        || spawn["revision"] != 1
        || spawn["argv_bytes"]
            != serde_json::json!([
                b"--exact".to_vec(),
                test.as_bytes().to_vec(),
                b"--ignored".to_vec(),
                b"--test-threads=1".to_vec()
            ])
        || retired["format"] != "memcordon.linux-native-test-retirement"
        || retired["revision"] != 1
        || retired["process_id"] != worker.pid
        || retired["birth"] != worker.birth
        || retired["held_before_input_delivery"] != true
        || retired["retirement_observed"] != true
        || retired["same_image_helpers_absent"] != true
    {
        return Err("native recovery held selected worker/retirement differs".into());
    }
    for raw in [&spawn, &before, &retired] {
        if raw["image_sha256"] != e.executable_sha256 {
            return Err("native recovery held worker image differs".into());
        }
    }
    closed(&boundary["worker"], &["pid", "start_time"])?;
    if boundary["worker"]["pid"] != worker.pid || boundary["worker"]["start_time"] != worker.birth {
        return Err("native boundary adopts unrelated worker".into());
    }
    let checkpoint = json(&acquired.checkpoint)?;
    let account_intent = json(&acquired.account_intent)?;
    let account = validate_linux_component_fixture_acquisition(
        &checkpoint,
        &account_intent,
        custody.bytes(&acquired.account_readback)?,
        custody.bytes(&acquired.group_readback)?,
        &e.run_id,
        &index.source_commit,
        &index.source_tree_sha256,
        &index.version,
        &e.key.target,
    )?;
    let admin = text(&checkpoint, "admin_root")?;
    let scope = admin
        .strip_suffix("/component-package-admin")
        .ok_or("native recovery acquired admin scope differs")?;
    if input["artifact_root"] != format!("{scope}/recipes/{recipe}")
        || input["fixture_path"] != format!("{scope}/release-fixture.json")
    {
        return Err("native recovery original fixture scope differs".into());
    }
    for (field, expected) in [
        ("fixture", "recovery-fixture.json"),
        ("current_contract", "current-contract.json"),
        ("actual_activation", "current-activation.json"),
        ("journal", "boundary-journal.bin"),
        ("reference", "boundary-reference.json"),
    ] {
        let path = text(&boundary, field)?;
        if path != format!("{prefix}/{expected}") {
            return Err("native recovery boundary leaf is not confined original peer".into());
        }
        custody.bytes(path)?;
    }
    let native: LinuxPreAccountNative =
        serde_json::from_value(boundary["native"].clone()).map_err(|error| error.to_string())?;
    let ownership: LinuxRecoveryOwnership = wire::decode(custody.bytes(ownership_path)?)?;
    validate_linux_pre_account_native(
        &native,
        account.0,
        custody.bytes(text(&boundary, "reference")?)?,
        custody.bytes(&format!("{prefix}/export-receipt.json"))?,
    )?;
    validate_linux_recovery_ownership(
        &ownership,
        &native,
        custody.bytes(text(&boundary, "journal")?)?,
        custody.bytes(text(&boundary, "reference")?)?,
        &format!(
            "/var/lib/memcordon/sealed/{}.mixed-admission",
            native.attempt_id
        ),
        &ownership.account.reservation.path,
    )?;
    let journal = decode_journal(
        custody.bytes(text(&boundary, "journal")?)?,
        &native.attempt_id,
    )?;
    if journal["phase"] != "retiring" || journal["release_knowledge"] != "exec-observed" {
        return Err("native recovery original pre-account boundary phase differs".into());
    }
    let reservation: LinuxRecoveryReservationRecord =
        wire::decode(&ownership.account.reservation.bytes)?;
    let prepared = json(&format!("{prefix}/native-prepared.json"))?;
    closed(
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
    )?;
    let contract = json(text(&boundary, "current_contract")?)?;
    wire::validate_request(
        custody.bytes(text(&boundary, "current_contract")?)?,
        &e.key,
        OutcomeOrigin::Target,
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
    let fixture = json(text(&boundary, "fixture")?)?;
    closed(&fixture, &["contract", "registry"])?;
    let activation = json(text(&boundary, "actual_activation")?)?;
    if crate::linux_policy::activation_registry(&activation)? != &fixture["registry"]
        || activation["registry_digest"]
            != linux_registry_digest(&fixture["registry"], &e.key.target)?
        || !fixture["registry"]["images"]
            .as_array()
            .is_some_and(|images| {
                images.len() == 2
                    && images.contains(&checkpoint["images"]["runtime"])
                    && images.contains(&checkpoint["images"]["input"])
            })
    {
        return Err("native recovery actual activated image registry differs from original acquired definitions".into());
    }
    let mut current_original = fixture["contract"].clone();
    current_original["expected_epoch"] = activation["epoch"].clone();
    if prepared["format"] != "memcordon.mixed-prepared-observation"
        || prepared["revision"] != 2
        || prepared["authorizes_launch"] != false
        || admission["format"] != "memcordon.private-admission-metadata"
        || admission["revision"] != 2
        || admission["attempt_id"] != native.attempt_id
        || admission["request"] != contract
        || contract != current_original
        || admission["request_sha256"] != wire::v3_request_digest(&contract)?
        || admission["epoch"] != contract["expected_epoch"]
        || admission["profile_id"] != contract["authorized_profile"]
        || admission != &journal["mixed_admission_metadata"]
        || prepared["provider"]["source_commit"] != index.source_commit
        || checkpoint["legacy"] != fixture["registry"]["legacy"]
        || custody.hash(text(&boundary, "fixture")?)? != text(&input, "fixture_sha256")?
        || boundary["fixture_sha256"] != input["fixture_sha256"]
        || native.attempt_id != hex::encode(&challenge[..16])
        || native.root_layout != contract["root_layout"]
        || native.execution_identity != contract["execution_identity"]
    {
        return Err(
            "native recovery preparation substitutes original fixture/admission/root/epoch".into(),
        );
    }
    let mut identities = BTreeSet::new();
    for field in ["caller", "target", "namespace_init", "guardian"] {
        closed(&prepared[field], &["pid", "birth"])?;
        let pid = number(&prepared[field], "pid")?;
        let birth = number(&prepared[field], "birth")?;
        if pid == 0 || pid > i32::MAX as u64 || birth == 0 || !identities.insert(pid) {
            return Err("native recovery prepared family aliases process ownership".into());
        }
        let original = match field {
            "caller" => "frontend",
            _ => field,
        };
        if journal[original]["pid"] != pid || journal[original]["start_time"] != birth {
            return Err("native recovery prepared family crosses original journal birth".into());
        }
    }
    if journal["mixed_worker"]["pid"] != worker.pid
        || journal["mixed_worker"]["start_time"] != worker.birth
        || identities.contains(&u64::from(worker.pid))
    {
        return Err("native recovery journal worker ownership differs".into());
    }
    for field in [
        "user_namespace",
        "mount_namespace",
        "pid_namespace",
        "network_namespace",
        "ipc_namespace",
    ] {
        closed(&prepared[field], &["device", "inode"])?;
        if number(&prepared[field], "device")? == 0 || number(&prepared[field], "inode")? == 0 {
            return Err("native recovery prepared namespace absent".into());
        }
    }
    let namespace = &prepared["user_namespace"];
    let reference = json(text(&boundary, "reference")?)?;
    if reference != *admission
        || journal["mixed_cgroup_identity"]["inode"] != native.cgroup_retirement.cgroup_inode
        || native.export_path != format!("/run/memcordon/private-export-{}", native.attempt_id)
        || journal["mixed_export_intent"] != native.export_path
    {
        return Err("native recovery original reference/cgroup/export owner differs".into());
    }
    let export = json(&format!("{prefix}/export-receipt.json"))?;
    closed(
        &export,
        &[
            "format",
            "revision",
            "attempt_id",
            "root_layout",
            "identity",
            "files",
        ],
    )?;
    if export["format"] != "memcordon.private-export"
        || export["revision"] != 1
        || export["attempt_id"] != native.attempt_id
        || export["root_layout"] != native.root_layout
        || export["identity"] != native.execution_identity
        || export["files"]
            .as_array()
            .is_none_or(|files| files.len() > 256)
    {
        return Err("native recovery export receipt adopts another native root".into());
    }
    let mut paths = BTreeSet::new();
    for file in export["files"]
        .as_array()
        .ok_or("native recovery export file inventory absent")?
    {
        closed(file, &["path", "length", "sha256"])?;
        let path = text(file, "path")?;
        custody::validate_path(path)?;
        if !paths.insert(path) || number(file, "length")? > 64 * 1024 * 1024 {
            return Err("native recovery export file inventory repeated/unbounded".into());
        }
        digest(text(file, "sha256")?)?;
    }
    validate_linux_recovery_reservation(
        &reservation,
        &ownership,
        &worker,
        (number(namespace, "device")?, number(namespace, "inode")?),
        text(&journal, "boot_identity")?,
    )?;
    let identity = serde_json::json!({"run_id":e.run_id,"source_commit":index.source_commit,"source_tree_sha256":index.source_tree_sha256,"version":index.version});
    let deadline = json(&format!(
        "{base}/roles/compiler/native-operation-deadline.json"
    ))?;
    let acquisition_origin = json(&format!("{base}/roles/compiler/acquisition-origin.json"))?;
    closed(
        &acquisition_origin,
        &[
            "format",
            "revision",
            "source",
            "target",
            "job",
            "run_id",
            "run_attempt",
            "harnesses_sha256",
            "host_sha256",
            "deadline_sha256",
            "actor_sha256",
            "fixture_sha256",
        ],
    )?;
    if acquisition_origin["job"] != origin.job
        || acquisition_origin["run_attempt"] != origin.run_attempt
        || !acquisition_origin["actor_sha256"].is_null()
        || !acquisition_origin["fixture_sha256"].is_null()
        || acquisition_origin["harnesses_sha256"]
            != custody.hash(&format!("{base}/roles/compiler/measured-harnesses.json"))?
        || acquisition_origin["host_sha256"]
            != custody.hash(&format!("{base}/roles/compiler/native-host.json"))?
    {
        return Err("native recovery original acquisition job/harness/host differs".into());
    }
    closed(
        &deadline,
        &[
            "format",
            "revision",
            "source",
            "native_target",
            "started_unix_millis",
            "work_deadline_unix_millis",
            "cleanup_deadline_unix_millis",
        ],
    )?;
    let selected = &deadline["source"];
    let harnesses = json(&format!("{base}/roles/compiler/measured-harnesses.json"))?;
    closed(
        &harnesses,
        &["format", "revision", "source", "native_target", "roles"],
    )?;
    let roles = harnesses["roles"]
        .as_array()
        .filter(|roles| roles.len() == 2)
        .ok_or("native recovery original two harness roles absent")?;
    if harnesses["format"] != "memcordon.consumer-readiness.native-harnesses"
        || harnesses["revision"] != 1
        || harnesses["source"] != *selected
        || harnesses["native_target"] != e.key.target
    {
        return Err("native recovery original harness source differs".into());
    }
    for (role, kind, package, test_name, features) in [
        (
            "operational",
            "operational",
            "memcordon",
            "sealed_agent",
            Some("private-tcp,test-support"),
        ),
        (
            "parser",
            "parser",
            "memcordon-readiness-verifier",
            "contract",
            None,
        ),
    ] {
        let matches: Vec<_> = roles.iter().filter(|value| value["role"] == role).collect();
        if matches.len() != 1 {
            return Err("native recovery original harness role ambiguous".into());
        }
        let value = matches[0];
        closed(
            value,
            &[
                "role",
                "package",
                "test",
                "features",
                "executable",
                "sha256",
                "compiler_output",
                "compiler_errors",
            ],
        )?;
        if value["role"] != kind
            || value["package"] != package
            || value["test"] != test_name
            || value["features"]
                != serde_json::to_value(features).map_err(|error| error.to_string())?
        {
            return Err("native recovery original harness recipe differs".into());
        }
        for path in ["executable", "compiler_output", "compiler_errors"] {
            if text(value, path)?.is_empty() {
                return Err("native recovery original harness path absent".into());
            }
        }
        digest(text(value, "sha256")?)?;
        if role == "operational"
            && (value["sha256"] != e.executable_sha256
                || text(value, "executable")?.as_bytes() != program)
        {
            return Err("native recovery original operational harness image/path differs".into());
        }
    }
    let host = json(&format!("{base}/roles/compiler/native-host.json"))?;
    closed(
        &host,
        &[
            "format",
            "revision",
            "source",
            "target",
            "host",
            "compiler",
            "compiler_artifact",
            "compiler_length",
            "compiler_sha256",
            "compiler_path_stdout",
            "compiler_path_stderr",
            "compiler_identity_stdout",
            "compiler_identity_stderr",
        ],
    )?;
    if host["format"] != "memcordon.consumer-readiness.original-native-host"
        || host["revision"] != 1
        || host["source"] != *selected
        || host["target"] != e.key.target
        || host["host"] != serde_json::to_value(&build.host).map_err(|error| error.to_string())?
        || host["compiler_sha256"] != build.host.toolchain_sha256
        || host["compiler_artifact"] != "native-compiler.bin"
        || host["compiler_sha256"]
            != custody.hash(&format!("{base}/roles/compiler/native-compiler.bin"))?
        || host["compiler_length"].as_u64()
            != Some(
                custody
                    .bytes(&format!("{base}/roles/compiler/native-compiler.bin"))?
                    .len() as u64,
            )
        || host["compiler_length"]
            .as_u64()
            .is_none_or(|value| value == 0)
        || !text(&host, "compiler")?.starts_with('/')
    {
        return Err("native recovery original host/compiler association differs".into());
    }
    let source_matches = match selected["kind"].as_str() {
        Some("working") => {
            closed(selected, &["kind", "version", "commit"])?;
            selected["version"] == index.version && selected["commit"] == index.source_commit
        }
        Some("tagged") => {
            closed(selected, &["kind", "source"])?;
            closed(
                &selected["source"],
                &[
                    "format",
                    "revision",
                    "repository",
                    "tag_ref",
                    "commit",
                    "version",
                ],
            )?;
            selected["source"]["format"] == "memcordon.selected-source"
                && selected["source"]["revision"] == 1
                && selected["source"]["repository"].as_str() == index.repository.as_deref()
                && selected["source"]["tag_ref"] == format!("refs/tags/{}", index.version)
                && selected["source"]["commit"] == index.source_commit
                && selected["source"]["version"] == index.version
        }
        _ => false,
    };
    if !source_matches
        || index.repository.as_deref().is_none_or(str::is_empty)
        || origin.repository != index.repository
        || deadline["format"] != "memcordon.consumer-readiness.original-native-deadline"
        || deadline["revision"] != 1
        || deadline["native_target"] != e.key.target
        || deadline["work_deadline_unix_millis"] != work
        || deadline["cleanup_deadline_unix_millis"] != cleanup
        || work.checked_sub(number(&deadline, "started_unix_millis")?) != Some(140 * 60 * 1000)
        || cleanup.checked_sub(work) != Some(15 * 60 * 1000)
        || acquisition_origin["format"] != "memcordon.consumer-readiness.native-acquisition-origin"
        || acquisition_origin["revision"] != 1
        || acquisition_origin["target"] != e.key.target
        || acquisition_origin["run_id"] != e.run_id
        || acquisition_origin["source"] != *selected
        || acquisition_origin["deadline_sha256"]
            != custody.hash(&format!(
                "{base}/roles/compiler/native-operation-deadline.json"
            ))?
    {
        return Err(
            "native recovery renews/substitutes original repository/source acquisition cutoff"
                .into(),
        );
    }
    let invocation: LinuxRecoveryInvocation = wire::decode(custody.bytes(invocation_path)?)?;
    let process: LinuxRecoveryCommandProcess = wire::decode(custody.bytes(process_path)?)?;
    let capture: LinuxRecoveryCapture = wire::decode(custody.bytes(capture_path)?)?;
    validate_linux_recovery_command_process(
        &invocation,
        &process,
        &capture,
        custody.bytes(invocation_path)?,
        custody.bytes(owner_path)?,
        &deadline["source"],
        &identity,
        &e.component_recipe_id,
        &e.key.target,
        admin,
        custody.bytes(boundary_path)?,
        custody.bytes(ownership_path)?,
        work,
        cleanup,
    )?;
    let recovered: LinuxRecoveredOwnership = wire::decode(custody.bytes(recovered_path)?)?;
    validate_linux_recovered_ownership(
        &recovered,
        &ownership,
        custody.bytes(boundary_path)?,
        custody.bytes(ownership_path)?,
        custody.bytes(&acquired.checkpoint)?,
        &identity,
        &e.component_recipe_id,
        &e.key.target,
        account,
        work,
        cleanup,
    )?;
    let exit = json(&format!("{prefix}/native-exit.json"))?;
    closed(
        &exit,
        &["native_status", "input_delivered", "capture_complete"],
    )?;
    if exit["input_delivered"] != true || exit["capture_complete"] != true {
        return Err("native recovery input/capture did not complete".into());
    }
    match &e.recovery {
        LinuxRecoveryComponentEvidence::AccountRetirementCrash {
            controller_intent,
            crash_exit,
            ..
        } => {
            if controller_intent != &format!("{prefix}/native-crash-controller.json")
                || crash_exit != &format!("{prefix}/native-crash-exit.json")
                || !exit["native_status"].is_null()
            {
                return Err("native crash recipe adopts normal completion".into());
            }
            let intent: LinuxCrashIntent = wire::decode(custody.bytes(controller_intent)?)?;
            let crash: LinuxCrashExit = wire::decode(custody.bytes(crash_exit)?)?;
            let caller = LinuxRecoveryProcess {
                pid: number(&journal["frontend"], "pid")?
                    .try_into()
                    .map_err(|_| "native caller PID overflow")?,
                birth: number(&journal["frontend"], "start_time")?,
            };
            validate_linux_crash_controller(
                &intent,
                &crash,
                custody.bytes(boundary_path)?,
                &e.run_id,
                &e.component_recipe_id,
                &e.key.target,
                &e.executable_sha256,
                &worker,
                &caller,
            )?;
        }
        LinuxRecoveryComponentEvidence::LostTerminalResponse {
            delivery_receipt,
            completed_carrier,
            terminal_request,
            helper_retirements,
            ..
        } => {
            if delivery_receipt != &format!("{prefix}/lost-terminal-native-receipt.json")
                || completed_carrier != &format!("{prefix}/completed-terminal-carrier.json")
                || terminal_request != &format!("{prefix}/terminal-request.json")
                || helper_retirements != &format!("{prefix}/lost-terminal-helper-retirements.json")
                || exit["native_status"] != 0
            {
                return Err("native lost-terminal recipe omits genuine normal completion".into());
            }
            let receipt: LinuxLostTerminalReceipt = wire::decode(custody.bytes(delivery_receipt)?)?;
            validate_linux_lost_terminal_delivery(
                &receipt,
                &e.run_id,
                &e.component_recipe_id,
                &e.key.target,
                &worker,
                &challenge,
                &prefix,
                work,
                cleanup,
            )?;
            validate_completed(
                &json(completed_carrier)?,
                &json(terminal_request)?,
                custody.bytes(terminal_request)?,
                &native,
                &journal,
                &prepared,
                &json(helper_retirements)?,
                &challenge,
                &e.source_commit,
                &e.key.target,
            )?;
        }
    }
    Ok(())
}

pub(crate) fn decode_journal(bytes: &[u8], attempt: &str) -> VerificationResult<Value> {
    if bytes.is_empty() || bytes.len() > 4 * 1024 * 1024 {
        return Err("native recovery journal byte bound differs".into());
    }
    let envelope_text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
    let (body, checksum) = envelope_text
        .rsplit_once("digest=")
        .ok_or("native recovery journal checksum absent")?;
    if checksum != format!("{}\n", sha256(body.as_bytes())) {
        return Err("native recovery journal checksum differs".into());
    }
    let mut lines = body.lines();
    if lines.next() != Some("format=memcordon.private-native-journal")
        || lines.next() != Some("revision=1")
        || lines.next() != Some(format!("cgroup={attempt}").as_str())
    {
        return Err("native recovery journal envelope differs".into());
    }
    let payload = lines
        .next()
        .and_then(|line| line.strip_prefix("payload="))
        .ok_or("native recovery journal payload absent")?;
    if lines.next().is_some() {
        return Err("native recovery journal envelope extra field".into());
    }
    let record: Value = wire::decode(payload.as_bytes())?;
    let required = [
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
    ];
    let optional = [
        "mixed_export_intent",
        "mixed_root_staging_intent",
        "mixed_cgroup_identity",
        "mixed_staging_identity",
        "mixed_export_identity",
    ];
    if record.as_object().is_none_or(|object| {
        required.iter().any(|field| !object.contains_key(*field))
            || object.keys().any(|field| {
                !required.contains(&field.as_str()) && !optional.contains(&field.as_str())
            })
    }) || record["attempt_id"] != attempt
    {
        return Err("native recovery journal original attempt/schema differs".into());
    }
    digest(text(&record, "caller_envelope_digest")?)?;
    Ok(record)
}

fn validate_completed(
    carrier: &Value,
    request: &Value,
    request_bytes: &[u8],
    native: &LinuxPreAccountNative,
    journal: &Value,
    prepared: &Value,
    helpers: &Value,
    challenge: &[u8],
    source: &str,
    target: &str,
) -> VerificationResult<()> {
    closed(
        carrier,
        &[
            "kind",
            "carrier_revision",
            "provider_contract",
            "launch_wire",
            "outcome",
        ],
    )?;
    closed(
        request,
        &[
            "format",
            "revision",
            "contract",
            "native_launch",
            "attempt_deadline_millis",
        ],
    )?;
    if carrier["kind"] != "linux-mixed-private"
        || carrier["carrier_revision"] != 2
        || carrier["provider_contract"] != 4
        || carrier["launch_wire"] != 4
        || request["format"] != "memcordon.mixed-runtime-request"
        || request["revision"] != 2
        || !request["attempt_deadline_millis"].is_null()
    {
        return Err("lost-terminal raw carrier/request revisions differ".into());
    }
    let outcome = &carrier["outcome"];
    closed(
        outcome,
        &[
            "kind",
            "admission",
            "request_bytes_sha256",
            "provider",
            "execution",
            "retirement",
        ],
    )?;
    let execution = &outcome["execution"];
    let admission = &outcome["admission"];
    let actual_launch: Vec<u8> = serde_json::from_value(request["native_launch"].clone())
        .map_err(|error| error.to_string())?;
    let mut expected = 3u16.to_be_bytes().to_vec();
    expected.extend(0u64.to_be_bytes());
    let put = |output: &mut Vec<u8>, value: &[u8]| -> VerificationResult<()> {
        let length: u32 = value
            .len()
            .try_into()
            .map_err(|_| "native recovery recipe argument exceeds codec count")?;
        output.extend(length.to_be_bytes());
        output.extend(value);
        Ok(())
    };
    put(
        &mut expected,
        text(&request["contract"]["launch"], "entrypoint")?.as_bytes(),
    )?;
    expected.extend(3u32.to_be_bytes());
    for argument in [
        b"bytes-argv-status".as_slice(),
        hex::encode(challenge).as_bytes(),
        b"0".as_slice(),
    ] {
        put(&mut expected, argument)?;
    }
    expected.extend(0u32.to_be_bytes());
    expected.push(1);
    expected.extend((1024u64 * 1024 * 1024).to_be_bytes());
    expected.push(1);
    expected.extend(0u64.to_be_bytes());
    expected.extend([0, 1, 2]);
    for interval in [10u64, 100, 100, 100] {
        expected.extend(interval.to_be_bytes());
    }
    expected.extend(5u32.to_be_bytes());
    expected.extend([1, 2, 3, 4, 5, 0]);
    if actual_launch != expected {
        return Err("lost-terminal actual native recipe argv/budgets/descriptors differ".into());
    }
    expected.extend(
        hex::decode(wire::v3_request_digest(&request["contract"])?)
            .map_err(|error| error.to_string())?,
    );
    if admission["invocation_sha256"] != sha256(&expected) {
        return Err("lost-terminal admitted native launch hash differs".into());
    }
    closed(
        &outcome["provider"],
        &["generation", "source_commit", "runtime_manifest_sha256"],
    )?;
    closed(
        execution,
        &[
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
            "authorization_monotonic_millis",
            "post_exec_descriptor_count",
            "native_wait_status",
            "outcome_origin",
        ],
    )?;
    if outcome["kind"] != "executed"
        || outcome["request_bytes_sha256"] != sha256(request_bytes)
        || admission["attempt_id"] != native.attempt_id
        || admission["request"] != request["contract"]
        || admission["request_sha256"] != wire::v3_request_digest(&request["contract"])?
        || admission != &journal["mixed_admission_metadata"]
        || outcome["provider"]["source_commit"] != source
        || execution["host_target"] != target
        || execution["native_wait_status"] != 0
        || execution["outcome_origin"] != "native-exit"
        || execution["root_layout"] != native.root_layout
        || execution["execution_identity"] != native.execution_identity
    {
        return Err(
            "lost-terminal completed execution crosses original admission/native boundary".into(),
        );
    }
    if outcome["provider"] != prepared["provider"]
        || execution["boot_id"] != journal["boot_identity"]
        || execution["caller_uid"] != admission["caller_uid"]
        || number(execution, "target_uid")? == 0
        || number(execution, "target_gid")? == 0
        || execution["target_uid"] == execution["caller_uid"]
        || execution["init_uid"] != 0
        || execution["post_exec_descriptor_count"] != 3
        || number(execution, "authorization_monotonic_millis")? == 0
        || execution["root_device"] != prepared["root_device"]
        || execution["root_inode"] != prepared["root_inode"]
    {
        return Err("lost-terminal completed native credential/root authority differs".into());
    }
    for field in ["caller", "target", "namespace_init", "guardian"] {
        closed(&execution[field], &["pid", "birth"])?;
        if execution[field] != prepared[field] {
            return Err("lost-terminal execution adopts different prepared family".into());
        }
    }
    for field in [
        "user_namespace",
        "mount_namespace",
        "pid_namespace",
        "network_namespace",
        "ipc_namespace",
    ] {
        let caller = format!("caller_{field}");
        closed(&execution[field], &["device", "inode"])?;
        closed(&execution[&caller], &["device", "inode"])?;
        if execution[field] != prepared[field]
            || number(&execution[&caller], "device")? == 0
            || number(&execution[&caller], "inode")? == 0
            || ((execution[field] == execution[&caller]) != (field == "user_namespace"))
        {
            return Err("lost-terminal execution namespace isolation differs".into());
        }
    }
    for field in [
        "runtime_image",
        "input_image",
        "root_layout",
        "execution_identity",
    ] {
        if execution[field] != request["contract"][field] {
            return Err("lost-terminal execution immutable binding differs".into());
        }
    }
    for field in [
        "init_nondumpable",
        "no_new_privileges",
        "capabilities_empty",
        "target_authorized",
        "exec_observed",
    ] {
        if execution[field] != true {
            return Err("lost-terminal execution native observation absent".into());
        }
    }
    if execution["filter_abi"]
        != if target.starts_with("x86_64-") {
            "x86_64"
        } else {
            "aarch64"
        }
    {
        return Err("lost-terminal native filter ABI differs".into());
    }
    digest(text(execution, "filter_instruction_sha256")?)?;
    let retirement = &outcome["retirement"];
    closed(
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
    )?;
    if retirement["attempt_id"] != native.attempt_id
        || retirement["export_receipt_sha256"] != native.export_receipt_sha256
    {
        return Err("lost-terminal retirement crosses native boundary attempt/export".into());
    }
    for field in [
        "workload_empty",
        "init_reaped",
        "guardian_reaped",
        "relays_drained_and_closed",
        "namespace_references_closed",
        "root_references_closed",
        "staging_removed",
        "account_quiescent",
        "reservation_retired",
    ] {
        if retirement[field] != true {
            return Err("lost-terminal carrier has outstanding retirement".into());
        }
    }
    let helpers = helpers
        .as_array()
        .ok_or("lost-terminal helper retirements absent")?;
    if helpers.len() != 1 {
        return Err("lost-terminal original caller helper cardinality differs".into());
    }
    let caller = &journal["frontend"];
    closed(
        &helpers[0],
        &[
            "pid",
            "birth",
            "raw_wait_status",
            "exit_code",
            "signal",
            "pidfd_retirement_observed",
        ],
    )?;
    if helpers[0]["pid"] != caller["pid"]
        || helpers[0]["birth"] != caller["start_time"]
        || helpers[0]["pidfd_retirement_observed"] != true
    {
        return Err("lost-terminal original held caller did not retire".into());
    }
    let wait = helpers[0]["raw_wait_status"]
        .as_i64()
        .ok_or("lost-terminal caller raw wait absent")?;
    if !((wait == 9 && helpers[0]["signal"] == 9 && helpers[0]["exit_code"].is_null())
        || (wait == 0 && helpers[0]["exit_code"] == 0 && helpers[0]["signal"].is_null()))
    {
        return Err("lost-terminal caller native wait aliases settlement".into());
    }
    Ok(())
}
