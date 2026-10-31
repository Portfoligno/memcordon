use memcordon_ci::linux_allocation_checkpoint::{matches_gate, unpublished_guardian_ready};
use serde_json::{Value, json};

const WORKER: u32 = 321;
const CALLER: u32 = 1000;
const REQUEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn journal() -> Value {
    json!({
        "format":"memcordon.private-workload-journal", "revision":1,
        "request_sha256":REQUEST, "caller_uid":CALLER,
        "attempt_id":"01010101010101010101010101010101", "boot_id":"synthetic-boot",
        "cleanup_cutoff_nanos":null, "cleanup_boot_id":null,
        "association": {
            "format":"memcordon.workload-attempt", "revision":1,
            "attempt":vec![1u8;16], "challenge":vec![2u8;16],
            "request_sha256":REQUEST, "boot_id":"synthetic-boot",
            "provider": {"generation":"fixture-generation", "source_commit":"a".repeat(40), "runtime_manifest_sha256":REQUEST},
            "control":{"pid":311,"birth":111}
        },
        "request":{"request_sha256":REQUEST,"invocation_sha256":REQUEST,
            "resource_policy_sha256":REQUEST,"runtime_sha256":REQUEST,"input_sha256":REQUEST},
        "frontend":{"pid":310,"start_time":110},
        "control":{"pid":311,"start_time":111},
        "worker":{"pid":WORKER,"start_time":112},
        "guardian":{"pid":322,"start_time":113},
        "phase":"guardian-ready", "release":"not-released",
        "intents":{"cgroup":true,"input_staging":true,"root_staging":true,"footprint":true,
            "namespace_init":true,"target":true,"guardian":true},
        "namespace_init":null, "target":null, "native":null,
        "outcome":null, "terminal":null,
        "cgroup":{"device":4,"inode":501}, "staging":{"device":4,"inode":502},
        "input_staging":{"device":4,"inode":503}, "root":{"device":4,"inode":504},
        "network_namespace_inode":null,"output_files":[],"outstanding":[],"errors":[]
    })
}

#[test]
fn guardian_ready_allocation_intents_precede_native_identity_publication() {
    let original = journal();
    let bytes = serde_json::to_vec(&original).unwrap();
    assert!(unpublished_guardian_ready(&original));
    assert!(matches_gate(&original, WORKER, REQUEST, CALLER));
    for field in ["namespace_init", "target"] {
        assert_eq!(original["intents"][field], true);
        assert!(original[field].is_null());
    }
    assert_eq!(serde_json::to_vec(&original).unwrap(), bytes);
}

#[test]
fn every_allocation_intent_must_be_the_exact_durable_true_value() {
    for field in ["namespace_init", "target", "guardian"] {
        for wrong in [json!(false), Value::Null, json!(1), json!("true")] {
            let mut invalid = journal();
            invalid["intents"][field] = wrong;
            assert!(!unpublished_guardian_ready(&invalid), "{field}");
            assert!(!matches_gate(&invalid, WORKER, REQUEST, CALLER));
        }
        let mut invalid = journal();
        invalid["intents"].as_object_mut().unwrap().remove(field);
        assert!(!unpublished_guardian_ready(&invalid));
    }
}

#[test]
fn other_phases_release_knowledge_and_published_facts_cannot_select_this_stop() {
    for phase in [
        "allocated",
        "boundary-created",
        "target-gated",
        "release-intent",
        "execution-observed",
        "retiring",
        "retired",
        "cleanup-incomplete",
    ] {
        let mut invalid = journal();
        invalid["phase"] = phase.into();
        assert!(!unpublished_guardian_ready(&invalid), "{phase}");
    }
    for release in [json!("released"), json!("unknown"), Value::Null] {
        let mut invalid = journal();
        invalid["release"] = release;
        assert!(!unpublished_guardian_ready(&invalid));
    }
    for field in ["namespace_init", "target", "native", "outcome", "terminal"] {
        let mut published = journal();
        published[field] = json!({"pid":999,"start_time":114});
        assert!(!unpublished_guardian_ready(&published), "published {field}");
        assert!(!matches_gate(&published, WORKER, REQUEST, CALLER));
        let mut omitted = journal();
        omitted.as_object_mut().unwrap().remove(field);
        assert!(!unpublished_guardian_ready(&omitted), "omitted {field}");
    }
}

#[test]
fn acquisition_also_requires_original_event_worker_request_and_caller_binding() {
    for (field, wrong) in [
        ("format", json!("another-journal")),
        ("revision", json!(2)),
        (
            "request_sha256",
            json!("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
        ),
        ("caller_uid", json!(CALLER + 1)),
    ] {
        let mut invalid = journal();
        invalid[field] = wrong;
        assert!(unpublished_guardian_ready(&invalid));
        assert!(!matches_gate(&invalid, WORKER, REQUEST, CALLER), "{field}");
    }
    let mut foreign_worker = journal();
    foreign_worker["worker"]["pid"] = json!(WORKER + 1);
    assert!(unpublished_guardian_ready(&foreign_worker));
    assert!(!matches_gate(&foreign_worker, WORKER, REQUEST, CALLER));
    let original = journal();
    assert!(!matches_gate(&original, WORKER + 1, REQUEST, CALLER));
    assert!(!matches_gate(&original, WORKER, "foreign-request", CALLER));
    assert!(!matches_gate(&original, WORKER, REQUEST, CALLER + 1));
}
