//! Encoded record vectors only. Native identities in this factory are test
//! data; accepting them here does not claim that a native matrix was executed.
use super::persisted_case::PersistedCase;
use memcordon_core::workload_registry_v3::{
    ExclusiveIdentityDefinitionV3, RootLayoutDefinitionV1, RuntimeImageDefinitionV1,
};
use memcordon_readiness_verifier::*;
use serde::Serialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
const MANIFEST: &str = include_str!("../../../../ci/consumer-readiness-v1.toml");

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn bytes(value: &Value) -> Vec<u8> {
    serde_json::to_vec(value).unwrap()
}

pub fn crash_case() -> PersistedCase {
    recovery_case(false)
}
pub fn lost_terminal_case() -> PersistedCase {
    recovery_case(true)
}

fn recovery_case(lost_terminal: bool) -> PersistedCase {
    let target = "x86_64-unknown-linux-gnu";
    let run = "persisted-recovery-vector";
    let version = "0.5.8-dev";
    let commit = "a".repeat(40);
    let source_bytes = b"original source archive record vector";
    let tree = hash(source_bytes);
    let executable_bytes = b"original instrumented native recovery executable vector";
    let image = hash(executable_bytes);
    let recipe = "native-linux-x64";
    let native_recipe = if lost_terminal {
        "lost-terminal"
    } else {
        "account-retirement"
    };
    let test = if lost_terminal {
        "native_mixed_recovery::native_lost_terminal_response_emit_actual_receipt"
    } else {
        "native_mixed_recovery::native_account_retirement_boundary_emit_actual_receipt"
    };
    let base = format!("{target}/candidate-native/components");
    let prefix = format!("{base}/{native_recipe}");
    let path = |leaf: &str| format!("{prefix}/{leaf}");
    let acquired = |leaf: &str| format!("{base}/native-fixture/{leaf}");
    let scope = "/var/lib/memcordon-native-readiness/persisted-vector";
    let admin = format!("{scope}/component-package-admin");
    let resource_root = format!("{admin}/native-package-evidence/resources");
    let identity =
        json!({"run_id":run,"source_commit":commit,"source_tree_sha256":tree,"version":version});
    let cell = json!({"target":target,"channel":"candidate-native"});
    #[derive(Serialize)]
    struct Original<'a> {
        run_id: &'a str,
        source_commit: &'a str,
        source_tree_sha256: &'a str,
        version: &'a str,
    }
    let discriminator = hash(
        &serde_json::to_vec(&(
            Original {
                run_id: run,
                source_commit: &commit,
                source_tree_sha256: &tree,
                version,
            },
            ProductKey {
                target: target.into(),
                channel: "candidate-native".into(),
            },
        ))
        .unwrap(),
    );
    let discriminator = hex::decode(discriminator).unwrap();
    let account_name = format!(
        "mc-ready-{:x}",
        u64::from_le_bytes(discriminator[..8].try_into().unwrap())
    );
    let account = json!({"name":account_name,"uid":10000,"gid":10000,"intent":format!("{resource_root}/exclusive-account-intent.json"),
        "native_readback":format!("{resource_root}/exclusive-account-getent.bin"),"group_readback":format!("{resource_root}/exclusive-group-getent.bin")});
    let make_image = |id: &str, entry: &str| {
        json!({"format":"memcordon.runtime-image","revision":1,"image_id":id,"target":target,
        "entries":[{"kind":"regular","path":entry,"sha256":image,"size":executable_bytes.len(),"executable":true}],
        "entrypoints":[{"id":"owned-readiness","path":entry}],"library_directories":[],"startup_environment":[]})
    };
    let runtime = make_image("runtime", "bin/owned-readiness");
    let input_image = make_image("input", "inputs/owned-readiness");
    let runtime_reference = serde_json::to_value(
        serde_json::from_value::<RuntimeImageDefinitionV1>(runtime.clone())
            .unwrap()
            .reference()
            .unwrap(),
    )
    .unwrap();
    let input_reference = serde_json::to_value(
        serde_json::from_value::<RuntimeImageDefinitionV1>(input_image.clone())
            .unwrap()
            .reference()
            .unwrap(),
    )
    .unwrap();
    let exclusive = json!({"identity_id":"exclusive","enabled":true,"uid":10000,"gid":10000,"supplementary_groups":[],
        "exclusive_use_policy":{"id":"exclusive-use","digest":hash(b"exclusive native identity policy")},"reservation_key":"exclusive-reservation"});
    let execution_identity = serde_json::to_value(
        serde_json::from_value::<ExclusiveIdentityDefinitionV3>(exclusive.clone())
            .unwrap()
            .reference()
            .unwrap(),
    )
    .unwrap();
    let layout = json!({"format":"memcordon.root-layout","revision":1,"layout_id":"root","runtime_image":runtime_reference,"input_image":input_reference,
        "writable_roots":[{"id":"work","path":"work","byte_limit":4096,"generated_execution":true}],"output_files":[]});
    let layout_reference = serde_json::to_value(
        serde_json::from_value::<RootLayoutDefinitionV1>(layout.clone())
            .unwrap()
            .reference()
            .unwrap(),
    )
    .unwrap();
    let legacy = json!({"format":"memcordon.local-private-policy","revision":1,"profiles":[],"execution_identities":[],"grants":[],"active_attempt_disposition":"drain-existing"});
    let profile =
        serde_json::to_value(memcordon_core::workload_registry_v3::profile_reference()).unwrap();
    let plan = hash(b"original workload plan");
    let registry = json!({"format":"memcordon.local-private-policy","revision":2,"legacy":legacy,"execution_identities":[exclusive],"images":[runtime,input_image],
        "root_layouts":[layout],"grants":[{"id":"current","revision":1,"enabled":true,"callers":[{"platform":"linux","uid":65534}],
        "approved_plans":[plan],"profile":profile,"execution_identity":execution_identity,"runtime_image":runtime_reference,"input_image":input_reference,"root_layout":layout_reference}],
        "active_attempt_disposition":"drain-existing"});
    let old_epoch = json!({"service_instance":vec![1u8;16],"revision":1});
    let epoch = json!({"service_instance":vec![2u8;16],"revision":5});
    let contract = json!({"schema_version":3,"workload_plan_digest":plan,"authorized_profile":profile,
        "authorization":{"grant_id":"current","grant_revision":1,"approved_plan_digest":plan},"ceiling":"fresh_root_ipv4_tcp_unix_streams_intra_attempt_no_gain",
        "requirements":[{"kind":"tcp_listener","id":"tcp","local_port":{"kind":"kernel_assigned"},"peer":{"kind":"dynamic_loopback_within_this_attempt"}},
            {"kind":"unix_stream_pair","id":"pair"},{"kind":"unix_path_stream","id":"pathname","writable_root":"work"},
            {"kind":"unix_abstract_stream","id":"abstract"},{"kind":"intra_attempt_descriptor_transfer","id":"rights"},
            {"kind":"generated_executable","id":"generated","writable_root":"work"}],"execution_identity":execution_identity,"runtime_image":runtime_reference,"input_image":input_reference,"root_layout":layout_reference,
        "launch":{"entrypoint":"owned-readiness","working_directory":"work"},"expected_epoch":old_epoch});
    let fixture = json!({"contract":contract,"registry":registry});
    let mut current = contract.clone();
    current["expected_epoch"] = epoch.clone();
    let registry_digest = linux_registry_digest(&registry, target).unwrap();
    let activation = json!({"format":"memcordon.local-private-activation","revision":2,"registry":registry,"registry_digest":registry_digest,"epoch":epoch,"revoked_admissions":[]});
    let challenge = vec![7u8; 32];
    let attempt = hex::encode(&challenge[..16]);
    let boot = "12345678-1234-1234-1234-123456789abc";
    let admitted: memcordon_core::workload_contract_v3::WorkloadContractV3 =
        serde_json::from_value(current.clone()).unwrap();
    let mut launch = 3u16.to_be_bytes().to_vec();
    launch.extend(0u64.to_be_bytes());
    let put = |out: &mut Vec<u8>, value: &[u8]| {
        out.extend((value.len() as u32).to_be_bytes());
        out.extend(value);
    };
    put(&mut launch, b"owned-readiness");
    launch.extend(3u32.to_be_bytes());
    for argument in [
        b"bytes-argv-status".as_slice(),
        hex::encode(&challenge).as_bytes(),
        b"0".as_slice(),
    ] {
        put(&mut launch, argument);
    }
    launch.extend(0u32.to_be_bytes());
    launch.push(1);
    launch.extend((1024u64 * 1024 * 1024).to_be_bytes());
    launch.push(1);
    launch.extend(0u64.to_be_bytes());
    launch.extend([0, 1, 2]);
    for interval in [10u64, 100, 100, 100] {
        launch.extend(interval.to_be_bytes());
    }
    launch.extend(5u32.to_be_bytes());
    launch.extend([1, 2, 3, 4, 5, 0]);
    let mut bound_launch = launch.clone();
    bound_launch.extend(Sha256::digest(admitted.canonical_bytes().unwrap()));
    let admission = json!({"format":"memcordon.private-admission-metadata","revision":2,"attempt_id":attempt,"request":current,
        "request_sha256":hash(&admitted.canonical_bytes().unwrap()),"invocation_sha256":hash(&bound_launch),"caller_uid":65534,
        "registry_digest":registry_digest,"epoch":epoch,"admission_nonce":vec![9u8;16],"profile_id":profile});
    let process = |pid: u32, birth: u64| json!({"pid":pid,"birth":birth});
    let journal_process = |pid: u32, birth: u64| json!({"pid":pid,"start_time":birth});
    let namespace = |inode: u64| json!({"device":1,"inode":inode});
    let prepared = json!({"format":"memcordon.mixed-prepared-observation","revision":2,"provider":{"generation":format!("{version}:{commit}"),"source_commit":commit,"runtime_manifest_sha256":hash(b"runtime manifest")},
        "admission":admission,"caller":process(102,301),"target":process(103,302),"namespace_init":process(104,303),"guardian":process(105,304),
        "user_namespace":namespace(100),"mount_namespace":namespace(101),"pid_namespace":namespace(102),"network_namespace":namespace(103),"ipc_namespace":namespace(104),
        "root_device":1,"root_inode":900,"authorizes_launch":false});
    let journal = json!({"attempt_id":attempt,"boot_identity":boot,"frontend":journal_process(102,301),"caller_envelope_digest":hash(b"native caller envelope"),
        "admission_metadata":null,"phase":"retiring","release_knowledge":"exec-observed","binding":null,"guardian":journal_process(105,304),
        "namespace_init":journal_process(104,303),"target":journal_process(103,302),"network_namespace_inode":103,"checkpoint":null,"checkpoint_digest":null,
        "gated_facts":null,"cleanup_error":null,"mixed_admission_metadata":admission,"mixed_worker":journal_process(101,300),
        "mixed_export_intent":format!("/run/memcordon/private-export-{attempt}"),"mixed_cgroup_identity":{"inode":400}});
    let body = format!(
        "format=memcordon.private-native-journal\nrevision=1\ncgroup={attempt}\npayload={journal}\n"
    );
    let journal_bytes = format!("{body}digest={}\n", hash(body.as_bytes())).into_bytes();
    let reference_bytes = bytes(&admission);
    let export = json!({"format":"memcordon.private-export","revision":1,"attempt_id":attempt,"root_layout":layout_reference,"identity":execution_identity,"files":[]});
    let reference = json!({"device":1,"inode":401,"length":reference_bytes.len(),"links":1,"uid":0,"mode":0o100600,"named_absent":false,"account_uid":10000,"retired":false});
    let native = json!({"attempt_id":attempt,"native_wait_status":0,"cgroup_retirement":{"schema_version":1,"cgroup_path":format!("/sys/fs/cgroup/memcordon-sealed/{attempt}"),
        "cgroup_inode":400,"last_members":[],"empty_monotonic_ns":100,"removed_monotonic_ns":101},"root_layout":layout_reference,"execution_identity":execution_identity,
        "export_path":format!("/run/memcordon/private-export-{attempt}"),"export_receipt_sha256":hash(&bytes(&export)),"admission_reference":reference});
    let reservation = json!({"format":"memcordon.account-reservation","revision":1,"user_namespace_device":1,"user_namespace_inode":100,"uid":10000,
        "attempt":challenge[..16],"owner_pid":101,"owner_birth":300,"boot_identity":boot});
    let reservation_bytes = bytes(&reservation);
    let protected = "/var/lib/memcordon/sealed";
    let leaf = |path: &str, inode: u64, length: usize| {
        json!({"path":path,"device":1,"inode":inode,"length":length,"links":1,"uid":0,"mode":0o100600,
        "parent_device":1,"parent_inode":20,"parent_uid":0,"parent_mode":0o040700})
    };
    let mut owned_journal = leaf(&format!("{protected}/{attempt}"), 30, journal_bytes.len());
    owned_journal["parent_path"] = protected.into();
    let mut owned_reservation = leaf(
        &format!("{protected}/account-1-100-10000.reservation"),
        31,
        reservation_bytes.len(),
    );
    owned_reservation["bytes"] = json!(reservation_bytes);
    owned_reservation["sha256"] = hash(&reservation_bytes).into();
    let ownership = json!({"journal":owned_journal,"journal_sha256":hash(&journal_bytes),"account":{"attempt_id":attempt,"account_uid":10000,
        "reference_path":format!("{protected}/{attempt}.mixed-admission"),"reference":reference,"reservation":owned_reservation}});
    let work = 9_400_000u64;
    let cleanup = 10_300_000u64;
    let boundary = json!({"format":"memcordon.linux-pre-account-native-boundary","revision":1,"run_id":run,"recipe_id":recipe,"native_target":target,"test_name":test,
        "worker":journal_process(101,300),"challenge_sha256":hash(&challenge),"fixture":path("recovery-fixture.json"),"fixture_sha256":hash(&bytes(&fixture)),
        "current_contract":path("current-contract.json"),"actual_activation":path("current-activation.json"),"journal":path("boundary-journal.bin"),"reference":path("boundary-reference.json"),
        "native":native,"work_deadline_unix_millis":work,"cleanup_deadline_unix_millis":cleanup});
    let checkpoint = json!({"format":"memcordon.owned-readiness-resources","revision":1,"identity":identity,"cell":cell,"admin_root":admin,"device":1,"inode":200,
        "legacy":legacy,"images":{"runtime":runtime,"input":input_image,"runtime_definition":"runtime.json","input_definition":"input.json","runtime_source":"runtime","input_source":"input",
        "fixture_sha256":image,"native_linker":null,"import_receipts":[]},"account":account});
    let selected = json!({"kind":"working","version":version,"commit":commit});
    let owner = json!({"format":"memcordon.consumer-readiness.native-package-owner","revision":1,"source":selected,"distribution":{"target":target},
        "cleanup_agent":format!("{admin}/native-package-cleanup-agent"),"cleanup_agent_sha256":hash(b"cleanup agent image"),"cleanup_agent_device":1,"cleanup_agent_inode":500,"original_installation_absent":true,"legacy":legacy});
    let recovery_invocation = json!({"format":"memcordon.native-component-recovery-invocation","revision":1,"identity":identity,"run_id":run,"recipe_id":recipe,"native_target":target,
        "program":format!("{admin}/native-package-cleanup-agent").as_bytes(),"arguments":[b"package".to_vec(),b"policy".to_vec(),b"recover".to_vec(),b"--json".to_vec()],
        "working_directory":scope.as_bytes(),"executable_sha256":hash(b"cleanup agent image"),"environment":[],"package_owner_sha256":hash(&bytes(&owner)),
        "selected_program":{"device":1,"inode":500,"length":19,"links":1,"uid":0,"mode":0o100555},"work_deadline_unix_millis":work,"cleanup_deadline_unix_millis":cleanup,
        "boundary_sha256":hash(&bytes(&boundary)),"ownership_sha256":hash(&bytes(&ownership))});
    let response =
        bytes(&json!({"format":"memcordon.native-recovery","revision":1,"outstanding":[]}));
    let invocation_hash = hash(&bytes(&recovery_invocation));
    let capture = json!({"format":"memcordon.native-component-recovery-capture","revision":1,"invocation_sha256":invocation_hash,"native_wait_status":0,"status":0,
        "stdout":response,"stderr":[],"stdout_sha256":hash(&response),"stderr_sha256":hash(b"")});
    let recovery_process = json!({"format":"memcordon.native-component-recovery-process","revision":1,"invocation_sha256":invocation_hash,
        "creation":{"process_id":106,"birth":305,"image":{"device":1,"inode":500}},"native_wait_status":0,
        "retirement":{"process_id":106,"birth":305,"pidfd_retirement_observed":true}});
    let absent = |role: &str, path: String, original: &Value| {
        json!({"role":role,"basename":path.rsplit('/').next().unwrap(),"path":path,"original":original,
        "parent_path":protected,"parent_device":1,"parent_inode":20,"parent_uid":0,"parent_mode":0o040700,"native_errno":2})
    };
    let recovered = json!({"format":"memcordon.native-component-recovered-ownership","revision":1,"identity":identity,"run_id":run,"recipe_id":recipe,"native_target":target,
        "boundary_sha256":hash(&bytes(&boundary)),"ownership_sha256":hash(&bytes(&ownership)),"checkpoint_sha256":hash(&bytes(&checkpoint)),"attempt_id":attempt,
        "account_uid":10000,"account_gid":10000,"work_deadline_unix_millis":work,"cleanup_deadline_unix_millis":cleanup,
        "absent_owned_leaves":[absent("journal",format!("{protected}/{attempt}"),&owned_journal),absent("reference",format!("{protected}/{attempt}.mixed-admission"),&reference),
            absent("reservation",format!("{protected}/account-1-100-10000.reservation"),&owned_reservation)],
        "tasks":[{"pid":1,"tid":1,"birth":1,"uids":[0,0,0,0],"gids":[0,0,0,0],"groups":[]}]});
    let key = CaseKey {
        target: target.into(),
        channel: None,
        evidence_class: EvidenceClass::NativeComponentRegression,
        family: "L-LIFE-04".into(),
        scenario: if lost_terminal {
            "lost-terminal-response"
        } else {
            "crash-before-account-retirement"
        }
        .into(),
    };
    let record = CaseRecord {
        key: key.clone(),
        run_id: run.into(),
        state: CaseState::Passed,
        reason: None,
        evidence: Some(path("case-evidence.json")),
    };
    let index:EvidenceIndex=serde_json::from_value(json!({"format":"memcordon.consumer-readiness.evidence","revision":1,"profile":PROFILE,"run_id":run,"source_commit":commit,
        "source_tree_sha256":tree,"version":version,"manifest_sha256":hash(MANIFEST.as_bytes()),"repository":"example/memcordon","products":[],"component_builds":[{"target":target,"source_commit":commit,"source_tree_sha256":tree,
            "host":{"kernel":"Linux","native_target":target,"executable_target":target,"emulated":false,"toolchain_identity":"fixture compiler","toolchain_sha256":hash(b"compiler"),"lockfile_sha256":hash(b"lockfile")},
            "recipe_id":recipe,"recipe_sha256":hash(b"native recipe"),"executable":"native-executable.bin","instrumented":true,"actor_executable":null,"parser_executable":null}],
        "workflow_cells":[],"fixture_cases":[],"artifacts":[],"records":[record],"producer_origins":[{"job":"native-linux-x64","run_id":run,"run_attempt":1,"artifact_id":"123",
            "artifact_sha256":hash(b"bundle"),"bundle_artifact":"bundle.zip","source_commit":commit,"source_tree_sha256":tree,"version":version,"manifest_sha256":hash(MANIFEST.as_bytes()),"repository":"example/memcordon"}],
        "job_outcomes":[],"assessment_failures":[]})).unwrap();
    let mut case = PersistedCase {
        root: tempfile::tempdir().unwrap(),
        index,
        record,
    };
    case.write("native-executable.bin", executable_bytes);
    case.write("source.tar", source_bytes);
    for (leaf, value) in [
        ("recovery-fixture.json", fixture),
        ("current-contract.json", current.clone()),
        ("current-activation.json", activation),
        ("native-prepared.json", prepared.clone()),
        ("export-receipt.json", export),
        ("boundary-reference.json", admission.clone()),
        ("account-ownership.json", ownership),
        ("account-boundary.json", boundary.clone()),
        ("native-recovery-invocation.json", recovery_invocation),
        ("native-recovery-capture.json", capture),
        ("native-recovery-process.json", recovery_process),
        ("recovered-ownership.json", recovered),
    ] {
        case.json(&path(leaf), &value);
    }
    case.write(&path("boundary-journal.bin"), &journal_bytes);
    case.json(&acquired("owned-resources-acquired.json"), &checkpoint);
    case.json(&acquired("native-package-owner.json"), &owner);
    case.json(&acquired("exclusive-account-intent.json"),&json!({"format":"memcordon.owned-readiness-account-intent","revision":1,"run_id":run,"cell":cell,"account_name":account_name,"native_absence_verified":true,"creation_attempted":true}));
    case.write(
        &acquired("exclusive-account-getent.bin"),
        format!("{account_name}:x:10000:10000::/nonexistent:/usr/sbin/nologin\n").as_bytes(),
    );
    case.write(
        &acquired("exclusive-group-getent.bin"),
        format!("{account_name}:x:10000:\n").as_bytes(),
    );
    let deadline = json!({"format":"memcordon.consumer-readiness.original-native-deadline","revision":1,"source":selected,"native_target":target,"started_unix_millis":1_000_000,
        "work_deadline_unix_millis":work,"cleanup_deadline_unix_millis":cleanup});
    case.json(
        &format!("{base}/roles/compiler/native-operation-deadline.json"),
        &deadline,
    );
    let harnesses = json!({"format":"memcordon.consumer-readiness.native-harnesses","revision":1,"source":selected,"native_target":target,
        "roles":[{"role":"operational","package":"memcordon","test":"sealed_agent","features":"private-tcp,test-support","executable":"/native/instrumented-test","sha256":image,"compiler_output":"operational/stdout.bin","compiler_errors":"operational/stderr.bin"},
            {"role":"parser","package":"memcordon-readiness-verifier","test":"contract","features":null,"executable":"parser-executable.bin","sha256":hash(b"parser"),"compiler_output":"parser/stdout.bin","compiler_errors":"parser/stderr.bin"}]});
    let native_host = json!({"format":"memcordon.consumer-readiness.original-native-host","revision":1,"source":selected,"target":target,
        "host":case.index.component_builds[0].host,"compiler":"/native/rustc","compiler_artifact":"native-compiler.bin","compiler_length":8,"compiler_sha256":hash(b"compiler"),
        "compiler_path_stdout":"compiler-path.stdout","compiler_path_stderr":"compiler-path.stderr","compiler_identity_stdout":"compiler-identity.stdout","compiler_identity_stderr":"compiler-identity.stderr"});
    case.json(
        &format!("{base}/roles/compiler/measured-harnesses.json"),
        &harnesses,
    );
    case.json(
        &format!("{base}/roles/compiler/native-host.json"),
        &native_host,
    );
    case.write(
        &format!("{base}/roles/compiler/native-compiler.bin"),
        b"compiler",
    );
    case.json(&format!("{base}/roles/compiler/acquisition-origin.json"),&json!({"format":"memcordon.consumer-readiness.native-acquisition-origin","revision":1,"target":target,"run_id":run,"source":selected,
        "job":"native-linux-x64","run_attempt":1,"harnesses_sha256":hash(&bytes(&harnesses)),"host_sha256":hash(&bytes(&native_host)),"deadline_sha256":hash(&bytes(&deadline)),"actor_sha256":null,"fixture_sha256":null}));
    case.json(&path("native-input.json"),&json!({"run_id":run,"recipe_id":recipe,"native_target":target,"artifact_root":format!("{scope}/recipes/{native_recipe}"),"artifact_prefix":prefix,
        "challenge":challenge,"work_deadline_unix_millis":work,"cleanup_deadline_unix_millis":cleanup,"fixture_path":format!("{scope}/release-fixture.json"),"fixture_sha256":boundary["fixture_sha256"]}));
    case.json(&path("native-spawn-intent.json"),&json!({"format":"memcordon.linux-native-test-invocation","revision":1,"program_bytes":b"/native/instrumented-test",
        "argv_bytes":[b"--exact".to_vec(),test.as_bytes().to_vec(),b"--ignored".to_vec(),b"--test-threads=1".to_vec()],"environment_cleared":true,"image_sha256":image,"test_name":test}));
    case.json(&path("native-pre-input.json"),&json!({"process_id":101,"birth":300,"image_sha256":image,"held_before_input_delivery":true,"test_name":test}));
    case.json(&path("native-retirement.json"),&json!({"format":"memcordon.linux-native-test-retirement","revision":1,"process_id":101,"birth":300,"image_sha256":image,
        "held_before_input_delivery":true,"retirement_observed":true,"same_image_helpers_absent":true}));
    case.json(
        &path("native-exit.json"),
        &json!({"native_status":null,"input_delivered":true,"capture_complete":true}),
    );
    case.write(&path("stdout.bin"), b"");
    case.write(&path("stderr.bin"), b"");
    case.json(&path("native-crash-controller.json"),&json!({"format":"memcordon.linux-native-crash-intent","revision":1,"run_id":run,"recipe_id":recipe,"native_target":target,"worker_pid":101,"worker_birth":300,
        "worker_image_sha256":image,"boundary_sha256":hash(&bytes(&boundary)),"requested_signal":"SIGKILL","held_before_boundary":true,"caller":process(102,301)}));
    case.json(&path("native-crash-exit.json"),&json!({"format":"memcordon.linux-native-crash-exit","revision":1,"worker_pid":101,"worker_birth":300,"worker_image_sha256":image,"raw_wait_status":9,
        "native_signal":9,"native_exit_code":null,"worker_pidfd_retirement_observed":true,"caller_pidfd_retirements":[process(102,301)]}));
    if lost_terminal {
        case.mutate(&path("native-exit.json"), |value| {
            value["native_status"] = json!(0)
        });
        let terminal_request = json!({"format":"memcordon.mixed-runtime-request","revision":2,"contract":current,"native_launch":launch,"attempt_deadline_millis":null});
        let mut execution = json!({"host_target":target,"boot_id":boot,"caller_uid":65534,"caller_gid":65534,
            "root_device":1,"root_inode":900,"runtime_image":runtime_reference,"input_image":input_reference,"root_layout":layout_reference,
            "execution_identity":execution_identity,"target_uid":10000,"target_gid":10000,"supplementary_groups":[],"init_uid":0,
            "init_nondumpable":true,"no_new_privileges":true,"capabilities_empty":true,"filter_abi":"x86_64","filter_instruction_sha256":hash(b"original filter"),
            "target_authorized":true,"exec_observed":true,"authorization_monotonic_millis":1000,"post_exec_descriptor_count":3,"native_wait_status":0,"outcome_origin":"native-exit"});
        for role in ["caller", "target", "namespace_init", "guardian"] {
            execution[role] = prepared[role].clone();
        }
        for (ordinal, field) in [
            "user_namespace",
            "mount_namespace",
            "pid_namespace",
            "network_namespace",
            "ipc_namespace",
        ]
        .into_iter()
        .enumerate()
        {
            execution[field] = prepared[field].clone();
            execution[format!("caller_{field}")] = namespace(if ordinal == 0 {
                100
            } else {
                500 + ordinal as u64
            });
        }
        let retirement = json!({"attempt_id":attempt,"workload_empty":true,"init_reaped":true,"guardian_reaped":true,"relays_drained_and_closed":true,
            "namespace_references_closed":true,"root_references_closed":true,"staging_removed":true,"account_quiescent":true,"reservation_retired":true,"export_receipt_sha256":native["export_receipt_sha256"]});
        let carrier = json!({"kind":"linux-mixed-private","carrier_revision":2,"provider_contract":4,"launch_wire":4,"outcome":{"kind":"executed",
            "admission":admission,"request_bytes_sha256":hash(&bytes(&terminal_request)),"provider":prepared["provider"],"execution":execution,"retirement":retirement}});
        case.json(&path("completed-terminal-carrier.json"), &carrier);
        case.json(&path("terminal-request.json"), &terminal_request);
        case.json(&path("lost-terminal-helper-retirements.json"),&json!([{"pid":102,"birth":301,"raw_wait_status":9,"exit_code":null,"signal":9,"pidfd_retirement_observed":true}]));
        case.json(&path("lost-terminal-native-receipt.json"),&json!({"format":"memcordon.linux-lost-terminal-component","revision":1,"run_id":run,"recipe_id":recipe,"native_target":target,"test_name":test,
            "worker":journal_process(101,300),"challenge_sha256":hash(&challenge),"carrier":path("completed-terminal-carrier.json"),"request":path("terminal-request.json"),"delivery_error":"Io(BrokenPipe)","native_errno":32,
            "work_deadline_unix_millis":work,"cleanup_deadline_unix_millis":cleanup}));
    }
    let mut evidence = LinuxNativeRecoveryCaseEvidence {
        format: "memcordon.consumer-readiness.linux-native-recovery".into(),
        revision: 1,
        key,
        run_id: run.into(),
        source_commit: commit,
        source_tree_sha256: tree.clone(),
        component_recipe_id: recipe.into(),
        executable: "native-executable.bin".into(),
        executable_sha256: image,
        source_artifact: "source.tar".into(),
        source_artifact_sha256: tree,
        invocation: path("native-spawn-intent.json"),
        native_preinput: path("native-pre-input.json"),
        native_retirement: path("native-retirement.json"),
        stdout: path("stdout.bin"),
        stderr: path("stderr.bin"),
        recovery: LinuxRecoveryComponentEvidence::AccountRetirementCrash {
            input: path("native-input.json"),
            boundary: path("account-boundary.json"),
            ownership: path("account-ownership.json"),
            controller_intent: path("native-crash-controller.json"),
            crash_exit: path("native-crash-exit.json"),
            recovery_invocation: path("native-recovery-invocation.json"),
            recovery_capture: path("native-recovery-capture.json"),
            recovery_process: path("native-recovery-process.json"),
            package_owner: acquired("native-package-owner.json"),
            recovered_ownership: path("recovered-ownership.json"),
            fixture_acquisition: ComponentFixtureAcquisition {
                checkpoint: acquired("owned-resources-acquired.json"),
                account_intent: acquired("exclusive-account-intent.json"),
                account_readback: acquired("exclusive-account-getent.bin"),
                group_readback: acquired("exclusive-group-getent.bin"),
            },
        },
    };
    if lost_terminal {
        let LinuxRecoveryComponentEvidence::AccountRetirementCrash {
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
        } = evidence.recovery
        else {
            unreachable!()
        };
        evidence.recovery = LinuxRecoveryComponentEvidence::LostTerminalResponse {
            input,
            boundary,
            ownership,
            recovery_invocation,
            recovery_capture,
            recovery_process,
            package_owner,
            recovered_ownership,
            fixture_acquisition,
            delivery_receipt: path("lost-terminal-native-receipt.json"),
            completed_carrier: path("completed-terminal-carrier.json"),
            terminal_request: path("terminal-request.json"),
            helper_retirements: path("lost-terminal-helper-retirements.json"),
        };
    }
    case.json(
        &path("case-evidence.json"),
        &serde_json::to_value(evidence).unwrap(),
    );
    case
}
