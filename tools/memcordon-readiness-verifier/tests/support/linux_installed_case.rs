//! Persisted decoder graphs only; no native execution or installed readiness claim.
use super::persisted_case::PersistedCase;
use memcordon_readiness_verifier::*;
use serde_json::{Value, json};

pub fn installed(family: &str, scenario: &str) -> PersistedCase {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let target = "x86_64-unknown-linux-gnu";
    let cell = ProductKey {
        target: target.into(),
        channel: "candidate-native".into(),
    };
    let key = CaseKey {
        target: target.into(),
        channel: Some(cell.channel.clone()),
        evidence_class: EvidenceClass::InstalledProduct,
        family: family.into(),
        scenario: scenario.into(),
    };
    let source = "a".repeat(40);
    let tree = "b".repeat(64);
    let version = "0.1.0-dev";
    let product:ProductObservation=serde_json::from_value(json!({"key":cell,"source_commit":source,"source_tree_sha256":tree,"version":version,
        "host":{"kernel":"linux","native_target":target,"executable_target":target,"emulated":false,"toolchain_identity":"retained decoder fixture","toolchain_sha256":"c".repeat(64),"lockfile_sha256":"d".repeat(64)},
        "features":["sealed-runtime","private-tcp"],"components":[{"role":"public-cli","artifact":"selected-cli.bin","installed_sha256":sha256(b"original CLI image")},{"role":"sealed-agent","artifact":"selected-agent.bin","installed_sha256":sha256(b"original agent image")}],
        "materialization":"decoder fixture","runtime_manifest":"runtime-manifest.json","package_sha256":"e".repeat(64),"registry_graph_sha256":null,"registry_graph":null,"request_revision":2,"result_revision":2,"runtime_profile":"linux-mixed-private",
        "lifecycle":{"lease_id":"original-lease","journal":"installed/lifecycle.json","receipt":"installed/lifecycle-receipt.json","journal_before_mutation":true,"installed_verified":true,"all_cases_inside_lease":true,"explicit_finalization":true,"finalization_records":1,"package_absent":true,"policy_retired":true,"native_resources_retired":true,"cleanup_failures":[],"outstanding":[],"predecessor_version":"0.0.9","predecessor_package_sha256":"f".repeat(64)}})).unwrap();
    let record = CaseRecord {
        key: key.clone(),
        run_id: "decoder-run".into(),
        state: CaseState::Passed,
        reason: None,
        evidence: Some("case-evidence.json".into()),
    };
    let index = EvidenceIndex {
        format: "memcordon.consumer-readiness.evidence".into(),
        revision: 1,
        profile: "decoder-vector".into(),
        run_id: "decoder-run".into(),
        source_commit: source.clone(),
        source_tree_sha256: tree.clone(),
        version: version.into(),
        manifest_sha256: "1".repeat(64),
        repository: None,
        products: vec![product],
        component_builds: vec![],
        workflow_cells: vec![cell.clone()],
        fixture_cases: vec![key],
        artifacts: vec![],
        records: vec![],
        producer_origins: vec![ProducerOrigin {
            job: "candidate-linux-x64-native".into(),
            run_id: "decoder-run".into(),
            run_attempt: 1,
            artifact_id: "original-decoder-origin".into(),
            artifact_sha256: sha256(b"original archive"),
            bundle_artifact: "original-archive.bin".into(),
            source_commit: source.clone(),
            source_tree_sha256: tree.clone(),
            version: version.into(),
            manifest_sha256: "1".repeat(64),
            repository: None,
        }],
        job_outcomes: vec![],
        assessment_failures: vec![],
    };
    let mut case = PersistedCase {
        root,
        index,
        record,
    };
    case.write("original-archive.bin", b"original archive");
    case.write("selected-cli.bin", b"original CLI image");
    case.write("selected-agent.bin", b"original agent image");
    case.json(
        "runtime-manifest.json",
        &json!({"format":"memcordon.sealed-runtime.manifest","revision":1}),
    );
    let identity = json!({"run_id":"decoder-run","source_commit":source,"source_tree_sha256":tree,"version":version});
    let admin = format!("{}/original-admin", case.root.path().display());
    let output = format!(
        "{}/installed/mixed-cases/image-cases",
        case.root.path().display()
    );
    let account = json!({"name":"original-account","uid":61001,"gid":61001,"intent":"original-account-intent","native_readback":"original-account-readback","group_readback":"original-group-readback"});
    let owner = json!({"format":"memcordon.linux-image-case-owner","revision":1,"identity":identity,"cell":cell,"lease_id":"original-lease","provider":{"generation":format!("{version}:{source}"),"source_commit":source,"runtime_manifest_sha256":sha256(&serde_json::to_vec(&json!({"format":"memcordon.sealed-runtime.manifest","revision":1})).unwrap())},"account":account,"expected_agent_sha256":sha256(b"original agent image"),"output":output,"admin_root":admin,"image_admin_root":format!("{admin}/image-cases/original-lease"),"admin_root_device":7,"admin_root_inode":8,"work_deadline_unix_millis":100,"cleanup_deadline_unix_millis":200});
    case.json("installed/mixed-cases/image-cases/owner.json", &owner);
    case.json("installed/lease-owner.json",&json!({"format":"memcordon.consumer-readiness.linux-lease-owner","revision":1,"identity":identity,"cell":cell,"admin_root":admin,"device":7,"inode":8,"cleanup_agent":"/usr/libexec/memcordon-sealed-agent","cleanup_agent_sha256":sha256(b"original agent image"),"legacy":null,"lease_id":"original-lease","artifact_root":case.root.path(),"work_deadline_unix_millis":100,"cleanup_deadline_unix_millis":200}));
    case.json(
        "installed/root-acquisition.json",
        &json!({"path":admin,"device":7,"inode":8}),
    );
    case.json("installed/lifecycle.json",&json!({"format":"memcordon.consumer-readiness.lifecycle-journal","revision":1,"run_id":"decoder-run","lease_id":"original-lease","key":cell,"source_commit":source,"source_tree_sha256":tree,"events":[{"sequence":1,"phase":"owned-before-mutation","operation":"administrative-staging-created","succeeded":true,"native_receipt":"installed/root-acquisition.json"}]}));
    case.json("installed/lifecycle-receipt.json", &json!({}));
    case.json("installed/owned-resources-acquired.json",&json!({"format":"memcordon.owned-readiness-resources","revision":1,"identity":identity,"cell":cell,"admin_root":admin,"device":7,"inode":8,"legacy":null,"images":{},"account":account}));
    let legacy = json!({"format":"memcordon.local-private-policy","revision":1,"profiles":[],"execution_identities":[],"grants":[],"active_attempt_disposition":"drain-existing"});
    case.mutate("installed/lease-owner.json", |raw| {
        raw["legacy"] = legacy.clone()
    });
    case.mutate("installed/owned-resources-acquired.json", |raw| {
        raw["legacy"] = legacy
    });
    case
}

pub fn read(case: &PersistedCase, path: &str) -> Value {
    serde_json::from_slice(&std::fs::read(case.root.path().join(path)).unwrap()).unwrap()
}

/// Original owned registry peers. This only constructs encoded vectors; it does not
/// stand in for native acquisition, preparation, execution, or retirement.
pub fn activation(
    case: &mut PersistedCase,
    runtime: Value,
    input: Value,
    outputs: Vec<String>,
    requirements: Value,
) -> (Value, Value, Value) {
    use memcordon_core::workload_contract_v3::RequirementV3;
    use memcordon_core::workload_registry_v3::{
        ExclusiveIdentityDefinitionV3, IMAGE_TOTAL_BYTES, RootLayoutDefinitionV1, profile_reference,
    };
    use memcordon_readiness_verifier::{linux_image_reference, linux_registry_digest, sha256};
    let owner = read(case, "installed/mixed-cases/image-cases/owner.json");
    case.mutate("installed/owned-resources-acquired.json", |raw| {
        raw["images"] = json!({"runtime":runtime,"input":input})
    });
    let declaration = json!({"format":"memcordon.owned-readiness-exclusive-use-declaration","revision":1,"run_id":owner["identity"]["run_id"],"cell":owner["cell"],"account":owner["account"]["name"],"uid":owner["account"]["uid"],"gid":owner["account"]["gid"],"purpose":"exclusive installed readiness attempt identity; no unrelated login or workload"});
    let exclusive = json!({"id":"owned-exclusive-use","digest":sha256(&serde_json::to_vec(&declaration).unwrap())});
    let identity = json!({"identity_id":"owned-readiness-identity","enabled":true,"uid":owner["account"]["uid"],"gid":owner["account"]["gid"],"supplementary_groups":[],"exclusive_use_policy":exclusive,"reservation_key":"owned-readiness-reservation"});
    let typed_identity: ExclusiveIdentityDefinitionV3 =
        serde_json::from_value(identity.clone()).unwrap();
    let execution = serde_json::to_value(typed_identity.reference().unwrap()).unwrap();
    let runtime_ref = linux_image_reference(&runtime, &case.record.key.target).unwrap();
    let input_ref = linux_image_reference(&input, &case.record.key.target).unwrap();
    let layout = json!({"format":"memcordon.root-layout","revision":1,"layout_id":"owned-readiness-root","runtime_image":runtime_ref,"input_image":input_ref,"writable_roots":[{"id":"work","path":"work","byte_limit":IMAGE_TOTAL_BYTES,"generated_execution":true}],"output_files":outputs});
    let typed_layout: RootLayoutDefinitionV1 = serde_json::from_value(layout.clone()).unwrap();
    let layout_ref = serde_json::to_value(typed_layout.reference().unwrap()).unwrap();
    let typed_requirements: Vec<RequirementV3> =
        serde_json::from_value(requirements.clone()).unwrap();
    let plan = sha256(
        &serde_json::to_vec(&(
            typed_layout.runtime_image.clone(),
            typed_layout.input_image.clone(),
            typed_layout.reference().unwrap(),
            typed_identity.reference().unwrap(),
            typed_requirements,
        ))
        .unwrap(),
    );
    let profile = serde_json::to_value(profile_reference()).unwrap();
    let epoch = json!({"service_instance":vec![8u8;16],"revision":1});
    let contract = json!({"schema_version":3,"workload_plan_digest":plan,"authorized_profile":profile,"authorization":{"grant_id":"owned-readiness-grant","grant_revision":1,"approved_plan_digest":plan},"ceiling":"fresh_root_ipv4_tcp_unix_streams_intra_attempt_no_gain","requirements":requirements,"execution_identity":execution,"runtime_image":runtime_ref,"input_image":input_ref,"root_layout":layout_ref,"launch":{"entrypoint":"owned-readiness","working_directory":"work"},"expected_epoch":epoch});
    let policy = json!({"format":"memcordon.local-private-policy","revision":2,"legacy":read(case,"installed/lease-owner.json")["legacy"],"execution_identities":[identity],"images":[runtime,input],"root_layouts":[layout],"grants":[{"id":"owned-readiness-grant","revision":1,"enabled":true,"callers":[{"platform":"linux","uid":65534}],"approved_plans":[plan],"profile":profile,"execution_identity":execution,"runtime_image":runtime_ref,"input_image":input_ref,"root_layout":layout_ref}],"active_attempt_disposition":"drain-existing"});
    let activation = json!({"format":"memcordon.local-private-activation","revision":2,"registry":policy,"registry_digest":linux_registry_digest(&policy,&case.record.key.target).unwrap(),"epoch":epoch,"revoked_admissions":[]});
    (contract, policy, activation)
}
