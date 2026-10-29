use memcordon_readiness_verifier::current::windows::validate_population_readiness;
use serde_json::json;
use std::collections::BTreeSet;

#[test]
fn population_requires_original_root_and_all_256_distinct_live_leaf_identities() {
    let root = (500u64, 700u64);
    let mut held = BTreeSet::from([root]);
    let mut rows = Vec::new();
    rows.push(json!({"kind":"inventory-root-ready","ordinal":null,"pid":root.0,"birth":root.1}));
    for ordinal in 0..256u64 {
        let identity = (1000 + ordinal, 2000 + ordinal);
        held.insert(identity);
        rows.push(json!({"kind":"inventory-leaf-ready","ordinal":ordinal,"pid":identity.0,"birth":identity.1}));
    }
    let encode = |rows: &[serde_json::Value]| {
        let mut output = Vec::new();
        for row in rows {
            output.extend_from_slice(b"MEMCORDON-INVENTORY-READY:");
            serde_json::to_writer(&mut output, row).unwrap();
            output.push(b'\n');
        }
        output
    };
    validate_population_readiness(&encode(&rows), &held, root).unwrap();
    assert!(validate_population_readiness(&encode(&rows[..256]), &held, root).is_err());
    let mut changed = rows.clone();
    changed[256] = changed[255].clone();
    assert!(validate_population_readiness(&encode(&changed), &held, root).is_err());
    let mut changed = rows.clone();
    changed[3]["birth"] = json!(8000);
    assert!(validate_population_readiness(&encode(&changed), &held, root).is_err());
    let mut changed = rows.clone();
    changed[3]["ordinal"] = json!(256);
    assert!(validate_population_readiness(&encode(&changed), &held, root).is_err());
    assert!(validate_population_readiness(&encode(&rows), &held, (root.0, root.1 + 1)).is_err());
}
