#[path = "support/persisted_case.rs"]
mod persisted_case;
#[path = "support/recovery_case.rs"]
mod recovery_case;

#[test]
fn crash_whole_persisted_original_record() {
    recovery_case::crash_case().validate().unwrap();
}

#[test]
fn crash_rejects_rehashed_cross_record_birth_and_fake_wait() {
    let prefix = "x86_64-unknown-linux-gnu/candidate-native/components/account-retirement";
    let mut birth = recovery_case::crash_case();
    birth.validate().unwrap();
    birth.mutate(&format!("{prefix}/account-boundary.json"), |value| {
        value["worker"]["start_time"] = serde_json::json!(999);
    });
    assert!(
        birth
            .validate()
            .unwrap_err()
            .contains("native boundary adopts unrelated worker"),
        "rehashed boundary must fail the independent worker birth join"
    );

    let mut wait = recovery_case::crash_case();
    wait.validate().unwrap();
    wait.mutate(&format!("{prefix}/native-crash-exit.json"), |value| {
        value["raw_wait_status"] = serde_json::json!(137 << 8);
        value["native_exit_code"] = serde_json::json!(137);
        value["native_signal"] = serde_json::Value::Null;
    });
    assert!(
        wait.validate()
            .unwrap_err()
            .contains("native crash wait/PIDFD retirement differs from requested native SIGKILL"),
        "shell-style exit 137 must fail the original native wait join"
    );
}

#[test]
fn crash_rejects_rehashed_open_schema() {
    let mut case = recovery_case::crash_case();
    case.validate().unwrap();
    let path = case.record.evidence.clone().unwrap();
    case.mutate(&path, |value| {
        value["claimed_cleanup_success"] = serde_json::json!(true);
    });
    assert!(
        case.validate().unwrap_err().contains("unknown field"),
        "unknown authority must fail the closed evidence envelope"
    );
}

#[test]
fn crash_rejects_json_substitute_for_original_durable_journal() {
    use sha2::{Digest, Sha256};
    let mut case = recovery_case::crash_case();
    case.validate().unwrap();
    let prefix = "x86_64-unknown-linux-gnu/candidate-native/components/account-retirement";
    let path = format!("{prefix}/boundary-journal.bin");
    let original = std::fs::read_to_string(case.root.path().join(&path)).unwrap();
    let payload = original
        .lines()
        .find_map(|line| line.strip_prefix("payload="))
        .unwrap()
        .as_bytes()
        .to_vec();
    // The payload remains valid JSON and all mutable custody hashes are updated.
    // Only the durable envelope, including its checksum, has been removed.
    case.write(&path, &payload);
    case.mutate(&format!("{prefix}/account-ownership.json"), |value| {
        value["journal_sha256"] = serde_json::json!(hex::encode(Sha256::digest(&payload)));
        value["journal"]["length"] = serde_json::json!(payload.len());
    });
    assert!(
        case.validate()
            .unwrap_err()
            .contains("native recovery journal checksum absent"),
        "valid JSON must reach and fail the independent durable envelope decoder"
    );
}

#[test]
fn crash_rejects_rehashed_original_harness_recipe_reassociation() {
    use sha2::{Digest, Sha256};
    let mut case = recovery_case::crash_case();
    case.validate().unwrap();
    let base = "x86_64-unknown-linux-gnu/candidate-native/components/roles/compiler";
    let path = format!("{base}/measured-harnesses.json");
    case.mutate(&path, |value| {
        value["roles"][0]["features"] = serde_json::json!("private-tcp");
    });
    let hash = hex::encode(Sha256::digest(
        std::fs::read(case.root.path().join(&path)).unwrap(),
    ));
    case.mutate(&format!("{base}/acquisition-origin.json"), |value| {
        value["harnesses_sha256"] = serde_json::json!(hash);
    });
    assert!(
        case.validate()
            .unwrap_err()
            .contains("native recovery original harness recipe differs"),
        "rehashing original acquisition must not hide changed operational test-support recipe"
    );
}

#[test]
fn crash_rejects_rehashed_executable_path_substitution() {
    let mut case = recovery_case::crash_case();
    case.validate().unwrap();
    let path = "x86_64-unknown-linux-gnu/candidate-native/components/account-retirement/native-spawn-intent.json";
    case.mutate(path, |value| {
        value["program_bytes"] = serde_json::json!(b"/other/native-test".to_vec());
    });
    assert!(
        case.validate()
            .unwrap_err()
            .contains("native recovery original operational harness image/path differs"),
        "same claimed image SHA must not substitute another original executable path"
    );
}

#[test]
fn lost_terminal_whole_persisted_original_record() {
    recovery_case::lost_terminal_case().validate().unwrap();
}

#[test]
fn lost_terminal_rejects_native_error_and_namespace_reassociations() {
    let prefix = "x86_64-unknown-linux-gnu/candidate-native/components/lost-terminal";
    let mut error = recovery_case::lost_terminal_case();
    error.validate().unwrap();
    error.mutate(
        &format!("{prefix}/lost-terminal-native-receipt.json"),
        |value| value["native_errno"] = serde_json::json!(137),
    );
    assert!(
        error
            .validate()
            .unwrap_err()
            .contains("native lost-terminal delivery differs"),
        "exit137 must not replace original EPIPE native delivery errno"
    );
    let mut namespace = recovery_case::lost_terminal_case();
    namespace.validate().unwrap();
    namespace.mutate(
        &format!("{prefix}/completed-terminal-carrier.json"),
        |value| {
            value["outcome"]["execution"]["caller_mount_namespace"] =
                value["outcome"]["execution"]["mount_namespace"].clone();
        },
    );
    assert!(
        namespace
            .validate()
            .unwrap_err()
            .contains("lost-terminal execution namespace isolation differs"),
        "completed carrier must preserve original caller/target mount isolation"
    );
}

#[test]
fn lost_terminal_rejects_rehashed_native_codec_and_renewed_cutoff() {
    use sha2::{Digest, Sha256};
    let prefix = "x86_64-unknown-linux-gnu/candidate-native/components/lost-terminal";
    let mut codec = recovery_case::lost_terminal_case();
    codec.validate().unwrap();
    let request = format!("{prefix}/terminal-request.json");
    codec.mutate(&request, |value| {
        value["native_launch"][1] = serde_json::json!(2)
    });
    let hash = hex::encode(Sha256::digest(
        std::fs::read(codec.root.path().join(&request)).unwrap(),
    ));
    codec.mutate(
        &format!("{prefix}/completed-terminal-carrier.json"),
        |value| value["outcome"]["request_bytes_sha256"] = serde_json::json!(hash),
    );
    assert!(
        codec
            .validate()
            .unwrap_err()
            .contains("lost-terminal actual native recipe argv/budgets/descriptors differ"),
        "updated rawrequest SHA must not hide unsupported native launch revision"
    );
    let mut cutoff = recovery_case::lost_terminal_case();
    cutoff.validate().unwrap();
    cutoff.mutate(
        &format!("{prefix}/lost-terminal-native-receipt.json"),
        |value| {
            value["work_deadline_unix_millis"] = serde_json::json!(9_400_001u64);
            value["cleanup_deadline_unix_millis"] = serde_json::json!(10_300_001u64);
        },
    );
    assert!(
        cutoff
            .validate()
            .unwrap_err()
            .contains("native lost-terminal delivery differs"),
        "receipt must not renew original native acquisition cutoffs"
    );
}
