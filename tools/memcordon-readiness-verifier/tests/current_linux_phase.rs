//! Data-only adversarial observation documents; no native experiment is claimed.
use memcordon_readiness_verifier::current::linux_owners::validate_preparation_namespace_observation;
use serde_json::{Value, json};

fn observation() -> Value {
    let roots:Vec<_>=[("journal","/var/lib/memcordon/workload-attempts"),("input-staging","/var/lib/memcordon/workload-inputs"),("footprint","/var/lib/memcordon/workload-resources"),("root-staging","/run/memcordon"),("cgroup","/sys/fs/cgroup/memcordon-sealed")].into_iter().enumerate().map(|(index,(role,path))|json!({"role":role,"path":path,"uid":0,"device":1,"inode":100+index,"mode":0o040700,"entries":[]})).collect();
    json!({"format":"memcordon.current-preparation-native-observation","revision":1,"before":roots,"blocked":roots,"after":roots,"events":[],"observer_entries":[],"locator_present":false})
}

#[test]
fn equal_final_census_does_not_hide_transient_native_allocation_or_assigned_locator() {
    let original = observation();
    validate_preparation_namespace_observation(&original).unwrap();
    let mut transient = original.clone();
    transient["events"] = json!([{"role":"journal","mask":256,"name":[97]}]);
    assert!(validate_preparation_namespace_observation(&transient).is_err());
    for field in ["observer_entries", "locator_present"] {
        let mut assigned = original.clone();
        assigned[field] = if field == "locator_present" {
            json!(true)
        } else {
            json!([[97]])
        };
        assert!(validate_preparation_namespace_observation(&assigned).is_err());
    }
}

#[test]
fn preparation_census_rejects_missing_rebound_or_unprotected_native_namespaces() {
    let original = observation();
    let mut omitted = original.clone();
    for phase in ["before", "blocked", "after"] {
        omitted[phase].as_array_mut().unwrap().pop();
    }
    assert!(validate_preparation_namespace_observation(&omitted).is_err());
    for (field, value) in [
        ("inode", json!(0)),
        ("uid", json!(1000)),
        ("mode", json!(0o040777)),
        ("path", json!("/tmp/imported")),
    ] {
        let mut changed = original.clone();
        for phase in ["before", "blocked", "after"] {
            changed[phase][0][field] = value.clone();
        }
        assert!(validate_preparation_namespace_observation(&changed).is_err());
    }
    let mut rebound = original;
    rebound["blocked"][0]["inode"] = json!(200);
    assert!(validate_preparation_namespace_observation(&rebound).is_err());
}
