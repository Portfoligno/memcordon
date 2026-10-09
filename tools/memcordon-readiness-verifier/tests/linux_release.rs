use memcordon_readiness_verifier::{
    LinuxReleaseGate, LinuxReleaseWait, validate_linux_release_gate,
};

#[allow(dead_code)]
#[path = "../../../crates/memcordon-cli/src/bin/memcordon-sealed-agent/request.rs"]
mod native_request;

#[test]
fn original_component_account_readbacks_cannot_be_redirected_or_reassociated() {
    use memcordon_readiness_verifier::{sha256, validate_linux_component_fixture_acquisition};
    let run = "run";
    let commit = "a".repeat(40);
    let tree = "b".repeat(64);
    let version = "0.1.0-dev";
    let target = "x86_64-unknown-linux-gnu";
    let original = format!(
        "[{{\"run_id\":\"{run}\",\"source_commit\":\"{commit}\",\"source_tree_sha256\":\"{tree}\",\"version\":\"{version}\"}},{{\"target\":\"{target}\",\"channel\":\"candidate-native\"}}]"
    );
    let digest = hex::decode(sha256(original.as_bytes())).unwrap();
    let name = format!(
        "mc-ready-{:x}",
        u64::from_le_bytes(digest[..8].try_into().unwrap())
    );
    let parent = "/var/lib/memcordon-native-readiness/owned/component-package-admin/native-package-evidence/resources";
    let cell = serde_json::json!({"target":target,"channel":"candidate-native"});
    let checkpoint = serde_json::json!({"format":"memcordon.owned-readiness-resources","revision":1,
        "identity":{"run_id":run,"source_commit":commit,"source_tree_sha256":tree,"version":version},"cell":cell,
        "admin_root":"/var/lib/memcordon-native-readiness/owned/component-package-admin","device":8,"inode":70,
        "legacy":{},"images":{"runtime":{},"input":{},"runtime_definition":"runtime.json","input_definition":"input.json",
            "runtime_source":"runtime","input_source":"input","fixture_sha256":"c".repeat(64),"native_linker":"linker","import_receipts":[]},"account":{"name":name,"uid":60001,"gid":60002,
            "intent":format!("{parent}/exclusive-account-intent.json"),"native_readback":format!("{parent}/exclusive-account-getent.bin"),
            "group_readback":format!("{parent}/exclusive-group-getent.bin")}});
    let intent = serde_json::json!({"format":"memcordon.owned-readiness-account-intent","revision":1,
        "run_id":run,"cell":cell,"account_name":name,"native_absence_verified":true,"creation_attempted":true});
    let passwd = format!("{name}:x:60001:60002::/nonexistent:/usr/sbin/nologin\n");
    let group = format!("{name}:x:60002:\n");
    let check = |checkpoint: &serde_json::Value,
                 intent: &serde_json::Value,
                 passwd: &[u8],
                 group: &[u8]| {
        validate_linux_component_fixture_acquisition(
            checkpoint, intent, passwd, group, run, &commit, &tree, version, target,
        )
    };
    // These are structural association vectors, not account creation/absence.
    assert_eq!(
        check(&checkpoint, &intent, passwd.as_bytes(), group.as_bytes()).unwrap(),
        (60001, 60002)
    );
    for field in ["intent", "native_readback", "group_readback"] {
        let mut changed = checkpoint.clone();
        changed["account"][field] = format!("{parent}/different-owned-file").into();
        assert!(check(&changed, &intent, passwd.as_bytes(), group.as_bytes()).is_err());
    }
    let mut changed = checkpoint.clone();
    changed["identity"]["run_id"] = "other-run".into();
    assert!(check(&changed, &intent, passwd.as_bytes(), group.as_bytes()).is_err());
    changed = checkpoint.clone();
    changed["account"]["uid"] = 60003.into();
    assert!(check(&changed, &intent, passwd.as_bytes(), group.as_bytes()).is_err());
    changed = checkpoint.clone();
    for (field, leaf) in [
        ("intent", "exclusive-account-intent.json"),
        ("native_readback", "exclusive-account-getent.bin"),
        ("group_readback", "exclusive-group-getent.bin"),
    ] {
        changed["account"][field]=format!("/var/lib/memcordon-native-readiness/another-owned/native-package-evidence/resources/{leaf}").into();
    }
    assert!(check(&changed, &intent, passwd.as_bytes(), group.as_bytes()).is_err());
    assert!(
        check(
            &checkpoint,
            &intent,
            passwd.as_bytes(),
            format!("{name}:x:60003:\n").as_bytes()
        )
        .is_err()
    );
}

#[test]
fn independent_effective_recipe_matches_native_codec_and_rejects_image_reassociation() {
    use memcordon_readiness_verifier::{linux_image_reference, linux_release_effective_invocation};
    use native_request::*;
    let target = "x86_64-unknown-linux-gnu";
    // Protocol/image vectors only: no native image is installed or executed.
    let image = |id: &str, path: &str, directories: Vec<&str>, name: &str, value: &str| {
        serde_json::json!({
        "format":"memcordon.runtime-image","revision":1,"image_id":id,"target":target,
        "entries":[{"kind":"regular","path":path,"sha256":"a".repeat(64),"size":1,"executable":true}],
        "entrypoints":[{"id":id,"path":path}],"library_directories":directories,
        "startup_environment":[{"name":name,"value":value}]})
    };
    let runtime = image(
        "runtime",
        "bin/owned",
        vec!["lib", "usr/lib"],
        "HOME",
        "/work",
    );
    let input = image(
        "input",
        "inputs/fixture",
        vec!["usr/lib", "inputs/lib"],
        "PATH",
        "/bin",
    );
    let fixture = serde_json::json!({"contract":{"runtime_image":linux_image_reference(&runtime,target).unwrap(),
        "input_image":linux_image_reference(&input,target).unwrap(),"launch":{"entrypoint":"runtime","working_directory":"work"}},
        "registry":{"images":[runtime,input]}});
    let native = LaunchRequestV2 {
        restart_attempt: 0,
        workload_contract: None,
        program: b"/bin/owned".to_vec(),
        arguments: vec![],
        environment: vec![
            (b"HOME".to_vec(), b"/work".to_vec()),
            (
                b"LD_LIBRARY_PATH".to_vec(),
                b"/lib:/usr/lib:/inputs/lib".to_vec(),
            ),
            (b"PATH".to_vec(), b"/bin".to_vec()),
        ],
        policy: LaunchPolicyV2 {
            memory_limit_bytes: Some(1024 * 1024 * 1024),
            swap_limit: SwapLimit::Bytes(0),
            absolute_deadline_millis: None,
            deadline_scope: DeadlineScope::Attempt,
            lifetime: Lifetime::Workload,
            poll_interval_millis: 10,
            signal_grace_millis: 100,
            command_exit_grace_millis: 100,
            limit_grace_millis: 100,
        },
        descriptors: vec![
            DescriptorPurpose::CurrentDirectory,
            DescriptorPurpose::Stdin,
            DescriptorPurpose::Stdout,
            DescriptorPurpose::Stderr,
            DescriptorPurpose::FrontendLiveness,
        ],
    };
    assert_eq!(
        linux_release_effective_invocation(&fixture, target).unwrap(),
        encode_launch_request(&native).unwrap()
    );
    let mut changed = fixture.clone();
    changed["registry"]["images"][0]["entrypoints"][0]["path"] = "bin/unmeasured".into();
    assert!(linux_release_effective_invocation(&changed, target).is_err());
    changed = fixture.clone();
    changed["registry"]["images"][1]["startup_environment"][0]["name"] = "HOME".into();
    changed["contract"]["input_image"] =
        linux_image_reference(&changed["registry"]["images"][1], target).unwrap();
    assert!(linux_release_effective_invocation(&changed, target).is_err());
}

#[test]
fn complete_release_receipt_rejects_rehashed_request_lease_and_native_owner_substitution() {
    use memcordon_core::workload_contract_v3::WorkloadContractV3;
    use memcordon_core::workload_registry_v3::{
        ExclusiveIdentityDefinitionV3, RootLayoutDefinitionV1, RuntimeImageDefinitionV1,
        RuntimePrivatePolicyRegistryV3,
    };
    use memcordon_readiness_verifier::{
        LinuxReleaseReceipt, linux_release_effective_invocation, sha256,
        validate_linux_release_receipt,
    };
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};
    let target = "x86_64-unknown-linux-gnu";
    let challenge = [7u8; 32];
    let prefix = "x86_64-unknown-linux-gnu/candidate-native/components/release";
    let image = |id: &str, path: &str| {
        json!({"format":"memcordon.runtime-image","revision":1,"image_id":id,"target":target,
        "entries":[{"kind":"regular","path":path,"sha256":"a".repeat(64),"size":1,"executable":true}],
        "entrypoints":[{"id":id,"path":path}],"library_directories":[],"startup_environment":[]})
    };
    let runtime = image("runtime", "bin/owned");
    let input = image("input", "inputs/fixture");
    let runtime_ref = serde_json::to_value(
        serde_json::from_value::<RuntimeImageDefinitionV1>(runtime.clone())
            .unwrap()
            .reference()
            .unwrap(),
    )
    .unwrap();
    let input_ref = serde_json::to_value(
        serde_json::from_value::<RuntimeImageDefinitionV1>(input.clone())
            .unwrap()
            .reference()
            .unwrap(),
    )
    .unwrap();
    let identity = json!({"identity_id":"account","enabled":true,"uid":60001,"gid":60002,"supplementary_groups":[],
        "exclusive_use_policy":{"id":"exclusive","digest":"e".repeat(64)},"reservation_key":"owned-reservation"});
    let identity_ref = serde_json::to_value(
        serde_json::from_value::<ExclusiveIdentityDefinitionV3>(identity.clone())
            .unwrap()
            .reference()
            .unwrap(),
    )
    .unwrap();
    let layout = json!({"format":"memcordon.root-layout","revision":1,"layout_id":"root","runtime_image":runtime_ref,"input_image":input_ref,
        "writable_roots":[{"id":"work","path":"work","byte_limit":67108864,"generated_execution":true}],"output_files":[]});
    let layout_ref = serde_json::to_value(
        serde_json::from_value::<RootLayoutDefinitionV1>(layout.clone())
            .unwrap()
            .reference()
            .unwrap(),
    )
    .unwrap();
    let profile = memcordon_core::workload_registry_v3::profile_reference();
    let registry = json!({"format":"memcordon.local-private-policy","revision":2,
        "legacy":{"format":"memcordon.local-private-policy","revision":1,"profiles":[],"execution_identities":[],"grants":[],"active_attempt_disposition":"drain-existing"},
        "execution_identities":[identity],"images":[runtime,input],"root_layouts":[layout],"grants":[{
            "id":"owned-grant","revision":1,"enabled":true,"callers":[{"platform":"linux","uid":65534}],"approved_plans":["d".repeat(64)],
            "profile":profile,"execution_identity":identity_ref,"runtime_image":runtime_ref,"input_image":input_ref,"root_layout":layout_ref}],
        "active_attempt_disposition":"drain-existing"});
    let actual_registry: RuntimePrivatePolicyRegistryV3 =
        serde_json::from_value(registry.clone()).unwrap();
    actual_registry.validate().unwrap();
    let registry_digest = hex::encode(actual_registry.canonical_digest().unwrap().bytes());
    let epoch = |revision: u64| json!({"service_instance":vec![1u8;16],"revision":revision});
    let mut contract = json!({"schema_version":3,"workload_plan_digest":"d".repeat(64),"authorized_profile":profile,
        "authorization":{"grant_id":"owned-grant","grant_revision":1,"approved_plan_digest":"d".repeat(64)},
        "ceiling":"fresh_root_ipv4_tcp_unix_streams_intra_attempt_no_gain",
        "requirements":[{"kind":"unix_stream_pair","id":"pair"}],
        "execution_identity":identity_ref,
        "runtime_image":runtime_ref,"input_image":input_ref,"root_layout":layout_ref,
        "launch":{"entrypoint":"runtime","working_directory":"work"},"expected_epoch":epoch(1)});
    let native_contract: WorkloadContractV3 = serde_json::from_value(contract.clone()).unwrap();
    native_contract.validate().unwrap();
    let fixture = json!({"contract":contract,"registry":registry});
    let fixture_bytes = serde_json::to_vec(&fixture).unwrap();
    let effective = linux_release_effective_invocation(&fixture, target).unwrap();
    let mut artifacts = std::collections::BTreeMap::<String, Vec<u8>>::new();
    let fixture_path = format!("{prefix}/release-fixture.json");
    artifacts.insert(fixture_path.clone(), fixture_bytes.clone());
    let wait = |pid: u32, birth: u64| json!({"pid":pid,"birth":birth,"raw_wait_status":9,"exit_code":null,"signal":9,"pidfd_retirement_observed":true});
    let mut observations = Vec::new();
    for (ordinal, stale) in [true, false].into_iter().enumerate() {
        let mut attempt = Sha256::new();
        attempt.update(challenge);
        attempt.update([u8::from(stale)]);
        let attempt = hex::encode(&attempt.finalize()[..16]);
        let actual: WorkloadContractV3 = serde_json::from_value(contract.clone()).unwrap();
        let request_sha = hex::encode(actual.digest().unwrap().bytes());
        let mut bound = effective.clone();
        bound.extend_from_slice(&hex::decode(&request_sha).unwrap());
        let metadata = json!({"format":"memcordon.private-admission-metadata","revision":2,"attempt_id":attempt,"request":contract,
            "request_sha256":request_sha,"invocation_sha256":sha256(&bound),"caller_uid":65534,"registry_digest":registry_digest,
            "epoch":contract["expected_epoch"],"admission_nonce":vec![ordinal as u8+1;16],"profile_id":profile});
        let reference = serde_json::to_vec(&metadata).unwrap();
        let record = json!({"attempt_id":attempt,"boot_identity":"native-boot","frontend":{"pid":42,"start_time":901},
            "caller_envelope_digest":"c".repeat(64),"admission_metadata":null,"phase":"allocated","release_knowledge":"not-released",
            "binding":null,"guardian":null,"namespace_init":null,"target":null,"network_namespace_inode":null,"checkpoint":null,
            "checkpoint_digest":null,"gated_facts":null,"cleanup_error":null,"mixed_admission_metadata":metadata,"mixed_worker":{"pid":77,"start_time":1000}});
        let body = format!(
            "format=memcordon.private-native-journal\nrevision=1\ncgroup={attempt}\npayload={}\n",
            serde_json::to_string(&record).unwrap()
        );
        let journal = format!("{body}digest={}\n", sha256(body.as_bytes())).into_bytes();
        let suffix = if stale { "stale" } else { "current" };
        let path = |leaf: &str| format!("{prefix}/{suffix}-{leaf}");
        artifacts.insert(path("effective-invocation.bin"), effective.clone());
        artifacts.insert(path("journal-before.bin"), journal.clone());
        artifacts.insert(path("journal-after.bin"), journal);
        artifacts.insert(path("reference.json"), reference.clone());
        let native = json!({"device":8,"inode":70+ordinal,"length":reference.len(),"links":1,"uid":0,"mode":0o100600,
            "named_absent":false,"account_uid":60001,"retired":false});
        let mut retired = native.clone();
        retired["links"] = 0.into();
        retired["named_absent"] = true.into();
        retired["retired"] = true.into();
        let activation = |epoch: Value| {
            json!({"format":"memcordon.local-private-activation","revision":2,"registry":registry,
            "registry_digest":registry_digest,"epoch":epoch,"revoked_admissions":[]})
        };
        observations.push(json!({"scenario":if stale{"stale-epoch-refused"}else{"current-epoch-released"},"metadata":metadata,
            "effective_invocation":path("effective-invocation.bin"),"journal_before":path("journal-before.bin"),"journal_after":path("journal-after.bin"),
            "reference":path("reference.json"),"reference_native_before":native,"reference_native_after":retired,
            "activation_before":activation(contract["expected_epoch"].clone()),"activation_after":activation(epoch(2)),
            "target_pid":43+ordinal,"target_birth":902+ordinal,"target_retirement":wait(43+ordinal as u32,902+ordinal as u64),
            "gate":{"refusal":if stale{Some("mixed epoch/grant changed before release")}else{None},"received":if stale{vec![]}else{vec![165]},"callbacks":if stale{0}else{1}},"private_root_materialized":false}));
        contract["expected_epoch"] = epoch(2);
    }
    let receipt:LinuxReleaseReceipt=serde_json::from_value(json!({"format":"memcordon.linux-leased-release-component","revision":1,
        "run_id":"run","recipe_id":"recipe","native_target":target,"test_name":"native_mixed_release::native_leased_release_emit_actual_component_receipt",
        "executable_sha256":"f".repeat(64),"challenge_sha256":sha256(&challenge),"fixture":fixture_path,"fixture_sha256":sha256(&fixture_bytes),
        "scope":"inner-leased-callback-no-private-root","observations":observations,"helper_retirement":[wait(42,901),wait(43,902),wait(44,903)]})).unwrap();
    let check = |receipt: &LinuxReleaseReceipt| {
        validate_linux_release_receipt(
            receipt,
            "run",
            "recipe",
            target,
            &"f".repeat(64),
            &challenge,
            (77, 1000),
            (60001, 60002),
            |path| {
                artifacts
                    .get(path)
                    .cloned()
                    .ok_or_else(|| "structural raw artifact absent".into())
            },
        )
    };
    // Real native codec inputs establish fixture validity; all receipts here
    // remain structural vectors, not executed policy or native-process proof.
    check(&receipt).unwrap();
    let mut changed = receipt.clone();
    changed.observations[1].metadata["request"]["launch"]["entrypoint"] = "other-entry".into();
    assert!(check(&changed).is_err());
    changed = receipt.clone();
    changed.observations[0].activation_after["epoch"]["revision"] = 1.into();
    assert!(check(&changed).is_err());
    changed = receipt.clone();
    changed.observations[1].target_retirement.birth = 999;
    assert!(check(&changed).is_err());
    changed = receipt.clone();
    changed.observations[1].reference_native_after.inode += 1;
    assert!(check(&changed).is_err());
}

#[test]
fn rehashed_journal_cannot_substitute_original_worker_caller_or_reference() {
    use memcordon_readiness_verifier::{
        LinuxReleaseObservation, sha256, validate_linux_release_ownership,
    };
    // Structural custody vectors only; no native leased callback is claimed.
    let metadata = serde_json::json!({"format":"memcordon.private-admission-metadata","revision":2,
        "attempt_id":"0123456789abcdef0123456789abcdef","request":{},"request_sha256":"a".repeat(64),
        "invocation_sha256":"b".repeat(64),"caller_uid":65534,"registry_digest":"c".repeat(64),
        "epoch":{},"admission_nonce":vec![1u8;16],"profile_id":"owned-profile"});
    let reference = serde_json::to_vec(&metadata).unwrap();
    let before = serde_json::json!({"device":8,"inode":70,"length":reference.len(),"links":1,"uid":0,
        "mode":0o100600,"named_absent":false,"account_uid":60001,"retired":false});
    let mut after = before.clone();
    after["links"] = 0.into();
    after["named_absent"] = true.into();
    after["retired"] = true.into();
    let wait = LinuxReleaseWait {
        pid: 41,
        birth: 900,
        raw_wait_status: 9,
        exit_code: None,
        signal: Some(9),
        pidfd_retirement_observed: true,
    };
    let observation:LinuxReleaseObservation=serde_json::from_value(serde_json::json!({
        "scenario":"stale-epoch-refused","metadata":metadata,"effective_invocation":"effective.bin",
        "journal_before":"before.bin","journal_after":"after.bin","reference":"reference.json",
        "reference_native_before":before,"reference_native_after":after,"activation_before":{},"activation_after":{},
        "target_pid":41,"target_birth":900,"target_retirement":wait,"gate":{"refusal":"mixed epoch/grant changed before release","received":[],"callbacks":0},
        "private_root_materialized":false})).unwrap();
    let record = serde_json::json!({"attempt_id":metadata["attempt_id"],"boot_identity":"native-boot",
        "frontend":{"pid":41,"start_time":900},"caller_envelope_digest":"d".repeat(64),
        "admission_metadata":null,"phase":"allocated","release_knowledge":"not-released","binding":null,
        "guardian":null,"namespace_init":null,"target":null,"network_namespace_inode":null,"checkpoint":null,
        "checkpoint_digest":null,"gated_facts":null,"cleanup_error":null,"mixed_admission_metadata":metadata,
        "mixed_worker":{"pid":77,"start_time":1000}});
    let encode = |record: &serde_json::Value| {
        let body = format!(
            "format=memcordon.private-native-journal\nrevision=1\ncgroup=0123456789abcdef0123456789abcdef\npayload={}\n",
            serde_json::to_string(record).unwrap()
        );
        format!("{body}digest={}\n", sha256(body.as_bytes())).into_bytes()
    };
    let original = encode(&record);
    assert!(
        validate_linux_release_ownership(
            &observation,
            &original,
            &original,
            &reference,
            (77, 1000),
            &wait,
            60001
        )
        .is_ok()
    );
    for field in ["mixed_worker", "frontend"] {
        let mut changed = record.clone();
        changed[field]["start_time"] = 1001.into();
        let bytes = encode(&changed);
        assert!(
            validate_linux_release_ownership(
                &observation,
                &bytes,
                &bytes,
                &reference,
                (77, 1000),
                &wait,
                60001
            )
            .is_err()
        );
    }
    let mut changed = record.clone();
    changed["target"] = serde_json::json!({"pid":41,"start_time":900});
    let bytes = encode(&changed);
    assert!(
        validate_linux_release_ownership(
            &observation,
            &bytes,
            &bytes,
            &reference,
            (77, 1000),
            &wait,
            60001
        )
        .is_err()
    );
    let mut changed = metadata.clone();
    changed["caller_uid"] = 60001.into();
    assert!(
        validate_linux_release_ownership(
            &observation,
            &original,
            &original,
            &serde_json::to_vec(&changed).unwrap(),
            (77, 1000),
            &wait,
            60001
        )
        .is_err()
    );
}

#[test]
fn retained_reference_cannot_be_reassociated_or_left_linked() {
    use memcordon_readiness_verifier::{LinuxReleaseReference, validate_linux_release_reference};
    let before = LinuxReleaseReference {
        device: 8,
        inode: 70,
        length: 200,
        links: 1,
        uid: 0,
        mode: 0o100600,
        named_absent: false,
        account_uid: 60001,
        retired: false,
    };
    let mut after = before.clone();
    after.links = 0;
    after.named_absent = true;
    after.retired = true;
    assert!(validate_linux_release_reference(&before, &after, 60001, 200).is_ok());
    let mut changed = after.clone();
    changed.inode += 1;
    assert!(validate_linux_release_reference(&before, &changed, 60001, 200).is_err());
    changed = after.clone();
    changed.links = 1;
    assert!(validate_linux_release_reference(&before, &changed, 60001, 200).is_err());
    changed = after.clone();
    changed.account_uid = 60002;
    assert!(validate_linux_release_reference(&before, &changed, 60001, 200).is_err());
    assert!(validate_linux_release_reference(&before, &after, 60001, 201).is_err());
}

#[test]
fn actual_gate_observations_require_bound_native_wait_and_exact_callback() {
    // Structural vectors; these do not claim a native policy lease execution.
    let wait = LinuxReleaseWait {
        pid: 41,
        birth: 900,
        raw_wait_status: 9,
        exit_code: None,
        signal: Some(9),
        pidfd_retirement_observed: true,
    };
    let mut stale = LinuxReleaseGate {
        refusal: Some("mixed epoch/grant changed before release".into()),
        received: vec![],
        callbacks: 0,
    };
    assert!(validate_linux_release_gate("stale-epoch-refused", &stale, &wait, 41, 900).is_ok());
    stale.callbacks = 1;
    assert!(validate_linux_release_gate("stale-epoch-refused", &stale, &wait, 41, 900).is_err());
    let current = LinuxReleaseGate {
        refusal: None,
        received: vec![165],
        callbacks: 1,
    };
    assert!(
        validate_linux_release_gate("current-epoch-released", &current, &wait, 41, 900).is_ok()
    );
    let mut changed = wait.clone();
    changed.birth += 1;
    assert!(
        validate_linux_release_gate("current-epoch-released", &current, &changed, 41, 900).is_err()
    );
    changed = wait.clone();
    changed.raw_wait_status = 137;
    assert!(
        validate_linux_release_gate("current-epoch-released", &current, &changed, 41, 900).is_err()
    );
    changed = wait.clone();
    changed.pidfd_retirement_observed = false;
    assert!(
        validate_linux_release_gate("current-epoch-released", &current, &changed, 41, 900).is_err()
    );
    let unknown =
        serde_json::json!({"refusal":null,"received":[165],"callbacks":1,"released":true});
    assert!(serde_json::from_value::<LinuxReleaseGate>(unknown).is_err());
}
