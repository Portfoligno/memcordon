use memcordon_readiness_verifier::*;
use serde_json::json;

#[test]
fn summary_cannot_erase_selected_features_conditional_edges_or_reachable_nodes() {
    for mutation in 0..4 {
        let temporary = tempfile::tempdir().unwrap();
        let metadata = json!({"packages":[{"id":"root","name":"root","version":"1.0.0"},{"id":"dep","name":"dep","version":"1.0.0"}],
            "resolve":{"root":"root","nodes":[{"id":"root","features":["selected"],"deps":[{"pkg":"dep","dep_kinds":[{"kind":"build","target":"cfg(unix)"}]}]},
                {"id":"dep","features":[],"deps":[]}]}});
        let edge = RegistryDependency {
            name: "dep".into(),
            version: "1.0.0".into(),
            kind: Some("build".into()),
            target: Some("cfg(unix)".into()),
        };
        let mut graph = RegistryGraph {
            format: "memcordon.consumer-readiness.registry-graph".into(),
            revision: 1,
            raw_metadata: "metadata.json".into(),
            raw_lock: "Cargo.lock".into(),
            packages: vec![
                RegistryPackage {
                    name: "root".into(),
                    version: "1.0.0".into(),
                    crate_sha256: sha256(b"root bytes"),
                    crate_artifact: "root.crate".into(),
                    features: vec!["selected".into()],
                    dependencies: vec![edge],
                },
                RegistryPackage {
                    name: "dep".into(),
                    version: "1.0.0".into(),
                    crate_sha256: sha256(b"dep bytes"),
                    crate_artifact: "dep.crate".into(),
                    features: vec![],
                    dependencies: vec![],
                },
            ],
        };
        match mutation {
            1 => graph.packages[0].features.clear(),
            2 => graph.packages[0].dependencies[0].target = None,
            3 => {
                graph.packages.pop();
            }
            _ => {}
        }
        let lock = format!(
            "version = 4\n[[package]]\nname = \"root\"\nversion = \"1.0.0\"\n[[package]]\nname = \"dep\"\nversion = \"1.0.0\"\nchecksum = \"{}\"\n",
            sha256(b"dep bytes")
        );
        let graph_bytes = serde_json::to_vec(&graph).unwrap();
        let graph_digest = sha256(&graph_bytes);
        let files = [
            ("metadata.json", serde_json::to_vec(&metadata).unwrap()),
            ("Cargo.lock", lock.into_bytes()),
            ("root.crate", b"root bytes".to_vec()),
            ("dep.crate", b"dep bytes".to_vec()),
            ("graph.json", graph_bytes),
        ];
        let artifacts = files
            .iter()
            .map(|(path, bytes)| {
                std::fs::write(temporary.path().join(path), bytes).unwrap();
                Artifact {
                    path: (*path).into(),
                    length: bytes.len() as u64,
                    sha256: sha256(bytes),
                }
            })
            .collect::<Vec<_>>();
        let observed = validate_cargo_graph_artifacts(
            temporary.path(),
            &artifacts,
            "graph.json",
            &graph_digest,
        );
        if mutation == 0 {
            assert_eq!(observed.unwrap().len(), 2);
        } else {
            assert!(observed.is_err(), "mutation {mutation}");
        }
    }
}
