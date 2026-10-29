use memcordon_readiness_verifier::{
    CaseKey, EvidenceClass,
    current::{CaseEvidenceV2, linux_package::verify_observed},
    sha256,
};
use serde_json::{Value, json};
use std::collections::BTreeMap;

fn sample() -> (CaseEvidenceV2, Value, BTreeMap<String, Vec<u8>>) {
    let fixture = b"measured current package executable".to_vec();
    let key = CaseKey {
        target: "x86_64-unknown-linux-gnu".into(),
        channel: Some("native".into()),
        family: "C-PACKAGE".into(),
        scenario: "fresh-install".into(),
        evidence_class: EvidenceClass::InstalledProduct,
    };
    let input = json!({"format":"memcordon.linux-current-package-input","revision":1,"run_id":"run","key":key,"lease_id":"lease","operation":"install","operation_receipt":"operation.json"});
    let operation = json!({"format":"memcordon.current-root-operation","revision":1,"lease_id":"lease","program":"/protected/selected/memcordon-sealed-agent","executable_sha256":sha256(&fixture),"arguments":["package","install"],"process":{"pid":42,"birth":0},"completed":{"status":0,"raw_wait_status":0,"stdout":[111,107],"stderr":[]}});
    let input_bytes = serde_json::to_vec(&input).unwrap();
    let evidence = CaseEvidenceV2 {
        format: "memcordon.consumer-readiness.case".into(),
        revision: 2,
        key,
        run_id: "run".into(),
        source_commit: "a".repeat(40),
        source_tree_sha256: "b".repeat(64),
        lease_id: Some("lease".into()),
        fixture: "agent.bin".into(),
        fixture_source: "source.tar".into(),
        fixture_sha256: sha256(&fixture),
        fixture_source_sha256: "b".repeat(64),
        input: "input.json".into(),
        input_sha256: sha256(&input_bytes),
        invocation: "operation.json".into(),
        request: None,
        raw_result: None,
        attempt_observation: None,
        authenticated_terminal: None,
        recovery: None,
        stdout: "stdout.bin".into(),
        stderr: "stderr.bin".into(),
        outputs: Vec::new(),
        native_observation: "operation.json".into(),
        retirement: "absence.json".into(),
        semantic_observation: "operation.json".into(),
        component_recipe_id: None,
    };
    (
        evidence,
        input,
        BTreeMap::from([
            ("agent.bin".into(), fixture),
            ("input.json".into(), input_bytes),
            (
                "operation.json".into(),
                serde_json::to_vec(&operation).unwrap(),
            ),
            ("stdout.bin".into(), b"ok".to_vec()),
            ("stderr.bin".into(), Vec::new()),
        ]),
    )
}

#[test]
fn fresh_current_install_requires_native_absence_before_the_actual_child() {
    let (mut evidence, mut input, mut files) = sample();
    evidence.key.family = "C-INSTALL-CURRENT".into();
    evidence.key.scenario = "fresh-without-registry".into();
    evidence.native_observation = "before.json".into();
    input["key"] = serde_json::to_value(&evidence.key).unwrap();
    let before = json!({"format":"memcordon.linux-current-fresh-install-before","revision":1,"lease_id":"lease",
        "paths":(["/sys/fs/cgroup/memcordon-sealed","/run/memcordon","/var/lib/memcordon/workload-attempts","/var/lib/memcordon/workload-inputs","/var/lib/memcordon/workload-resources"].map(|path|json!({"path":path,"absent":true}))),
        "package_images":[{"path":"/usr/libexec/memcordon-sealed-agent","absent":true}]});
    files.insert("before.json".into(), serde_json::to_vec(&before).unwrap());
    verify_observed(&evidence, &input, &|path| {
        files.get(path).cloned().ok_or_else(|| path.into())
    })
    .unwrap();
    let mut occupied = before;
    occupied["paths"][0]["absent"] = false.into();
    files.insert("before.json".into(), serde_json::to_vec(&occupied).unwrap());
    assert!(
        verify_observed(&evidence, &input, &|path| files
            .get(path)
            .cloned()
            .ok_or_else(|| path.into()))
        .is_err()
    );
}

#[test]
fn current_install_interruption_requires_successful_native_publication_and_original_child_reap() {
    use memcordon_readiness_verifier::current::linux_package::verify_interruption;
    let (mut evidence, _, mut files) = sample();
    evidence.key.family = "C-INSTALL-CURRENT".into();
    evidence.key.scenario = "interrupted-current-install".into();
    let mut operation: Value =
        serde_json::from_slice(&files.remove("operation.json").unwrap()).unwrap();
    operation["arguments"] = json!(["package", "upgrade"]);
    operation["completed"]["status"] = Value::Null;
    operation["completed"]["raw_wait_status"] = 9.into();
    let manifest = json!({"format":"memcordon.runtime-manifest","revision":2,"source_commit":evidence.source_commit,"target":evidence.key.target});
    let journal = json!({"format":"memcordon.current-package-transaction","revision":1,"phase":"preparing","entries":[{"path":"/usr/libexec/memcordon-sealed-agent","old_sha256":evidence.fixture_sha256,"old_device":1,"old_inode":12,"backup":"/usr/libexec/.memcordon-backup-example","stage":{"path":"/usr/libexec/.memcordon-stage-example","device":1,"inode":13,"mode":0o555,"sha256":evidence.fixture_sha256},"placeholder":{"path":"/usr/libexec/.memcordon-backup-example","device":1,"inode":14,"mode":0o600,"sha256":sha256(&[])}}]});
    let mut native = json!({"format":"memcordon.linux-current-install-interruption","revision":1,"lease_id":"lease",
        "manifest_before":manifest,"manifest_bytes_before":serde_json::to_vec(&manifest).unwrap(),
        "executable_identity":{"device":1,"inode":4,"length":40,"mode":0o100555,"uid":0,"sha256":evidence.fixture_sha256},
        "permission":{"mechanism":"fanotify-open-permission","scope_kind":"file","file_uid":0,"pid":42,"allow_written":true,"device":1,"inode":4,"file_length":40},
        "publication":{"mechanism":"ptrace-native-rename-exit","pid":42,"birth":0,"return_value":0,"worker_stopped_before_userspace":true,"destination":".memcordon-current-package-transaction.json","source":"/usr/libexec/.memcordon-journal-example","architecture":0xc000003e_u64,"syscall":82,"inode":5,"directory_inode":6,"record_bytes":serde_json::to_vec(&journal).unwrap()},
        "detached":{"pid":42,"birth":0,"ptrace_detached":true,"native_group_stop_observed":true,"exit_wait_consumed":false,"signal":19},
        "signal":9,"signal_result":0,"original_process_retired":{"pid":42,"birth":0,"pidfd_readable":true,"raw_wait_status":9}});
    let mut stage = journal["entries"][0]["stage"].clone();
    stage["uid"] = 0.into();
    stage["links"] = 1.into();
    let mut placeholder = journal["entries"][0]["placeholder"].clone();
    placeholder["uid"] = 0.into();
    placeholder["links"] = 1.into();
    native["file_inventory"] = json!([{"path":"/usr/libexec/memcordon-sealed-agent","target":{"path":"/usr/libexec/memcordon-sealed-agent","device":1,"inode":12,"mode":0o555,"uid":0,"links":1,"sha256":evidence.fixture_sha256},"stage":stage,"placeholder":placeholder}]);
    verify_interruption(&native, &operation, &evidence).unwrap();
    for (section, field, value) in [
        ("publication", "return_value", json!(-1)),
        ("publication", "birth", json!(1)),
        ("detached", "exit_wait_consumed", json!(true)),
        ("original_process_retired", "pidfd_readable", json!(false)),
        ("permission", "inode", json!(99)),
    ] {
        let mut changed = native.clone();
        changed[section][field] = value;
        assert!(
            verify_interruption(&changed, &operation, &evidence).is_err(),
            "{section}.{field}"
        );
    }
    for (role, field, value) in [
        ("stage", "inode", json!(99)),
        ("stage", "sha256", json!("0".repeat(64))),
        ("placeholder", "sha256", json!("1".repeat(64))),
        ("target", "inode", json!(77)),
    ] {
        let mut changed = native.clone();
        changed["file_inventory"][0][role][field] = value;
        assert!(
            verify_interruption(&changed, &operation, &evidence).is_err(),
            "{role}.{field}"
        );
    }
}

fn check(
    evidence: &CaseEvidenceV2,
    input: &Value,
    files: &BTreeMap<String, Vec<u8>>,
) -> Result<(), String> {
    verify_observed(evidence, input, &|path| {
        files
            .get(path)
            .cloned()
            .ok_or_else(|| format!("missing {path}"))
    })
}

#[test]
fn package_native_wait_custody_accepts_zero_birth_but_rejects_substitution() {
    let (evidence, input, files) = sample();
    check(&evidence, &input, &files).unwrap();
    for (pointer, replacement) in [
        ("/lease_id", json!("other")),
        ("/process/pid", json!(0)),
        ("/process/birth", Value::Null),
        ("/completed/raw_wait_status", json!(256)),
        ("/arguments", json!(["package", "install", "--extra"])),
        ("/program", json!("/other/program")),
        ("/executable_sha256", json!("c".repeat(64))),
        ("/revision", json!(2)),
    ] {
        let mut changed = files.clone();
        let mut receipt: Value = serde_json::from_slice(&changed["operation.json"]).unwrap();
        *receipt.pointer_mut(pointer).unwrap() = replacement;
        changed.insert(
            "operation.json".into(),
            serde_json::to_vec(&receipt).unwrap(),
        );
        assert!(check(&evidence, &input, &changed).is_err(), "{pointer}");
    }
}

#[test]
fn package_raw_stream_and_unknown_field_mutations_fail() {
    let (evidence, input, mut files) = sample();
    files.insert("stdout.bin".into(), b"changed".to_vec());
    assert!(check(&evidence, &input, &files).is_err());
    let (evidence, input, mut files) = sample();
    let mut receipt: Value = serde_json::from_slice(&files["operation.json"]).unwrap();
    receipt["unknown_authority"] = json!(true);
    files.insert(
        "operation.json".into(),
        serde_json::to_vec(&receipt).unwrap(),
    );
    assert!(check(&evidence, &input, &files).is_err());
}
