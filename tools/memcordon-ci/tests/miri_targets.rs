use memcordon_ci::miri_targets::{MiriTarget, plan};
use serde_json::{Value, json};

fn target(name: &str, kind: &str, test: bool, doctest: bool, required: &[&str]) -> Value {
    json!({"name":name,"kind":[kind],"test":test,"doctest":doctest,"required-features":required})
}

fn metadata(features: Value, targets: Vec<Value>) -> Vec<u8> {
    serde_json::to_vec(&json!({"packages":[{"name":"core","features":features,"targets":targets}]}))
        .unwrap()
}

#[test]
fn preserves_library_integration_docs_and_default_feature_selection() {
    let data = metadata(
        json!({"test-support":[]}),
        vec![
            target("core", "lib", true, true, &[]),
            target("diagnostics", "test", true, false, &[]),
            target("restart", "test", true, false, &["test-support"]),
        ],
    );
    assert_eq!(
        plan(&data, "core").unwrap(),
        vec![
            MiriTarget::Library,
            MiriTarget::Integration("diagnostics".into()),
            MiriTarget::Documentation,
        ]
    );
    assert_eq!(MiriTarget::Library.arguments(), ["--lib"]);
    assert_eq!(
        MiriTarget::Integration("diagnostics".into()).arguments(),
        ["--test", "diagnostics"]
    );
    assert_eq!(MiriTarget::Documentation.arguments(), ["--doc"]);
}

#[test]
fn discovers_new_targets_and_expands_only_local_default_features() {
    let data = metadata(
        json!({
        "default":["suite","dep:optional"],
            "suite":["enabled"],"enabled":["suite"],"extra":[],"optional":[],
        }),
        vec![
            target("new_safety_regression", "test", true, false, &[]),
            target("default_enabled", "test", true, false, &["enabled"]),
            target(
                "dependency_feature_is_not_local",
                "test",
                true,
                false,
                &["extra"],
            ),
            target(
                "explicit_dependency_is_not_local",
                "test",
                true,
                false,
                &["optional"],
            ),
        ],
    );
    assert_eq!(
        plan(&data, "core").unwrap(),
        vec![
            MiriTarget::Integration("default_enabled".into()),
            MiriTarget::Integration("new_safety_regression".into()),
        ]
    );
    for forwarding in ["optional/extra", "optional?/extra"] {
        let unsupported = metadata(
            json!({"default":[forwarding], "optional":["dep:optional"]}),
            vec![target("gated", "test", true, false, &["optional"])],
        );
        assert!(plan(&unsupported, "core").is_err());
    }
}

#[test]
fn supports_explicit_testable_kinds_and_rejects_unrepresented_coverage() {
    let data = metadata(
        json!({}),
        vec![
            target("tool", "bin", true, false, &[]),
            target("sample", "example", true, false, &[]),
            target("measurement", "bench", true, false, &[]),
        ],
    );
    assert_eq!(
        plan(&data, "core").unwrap(),
        vec![
            MiriTarget::Binary("tool".into()),
            MiriTarget::Example("sample".into()),
            MiriTarget::Bench("measurement".into()),
        ]
    );
    for unsupported in [
        target("compile_only_example", "example", false, false, &[]),
        target("unknown", "future-kind", true, false, &[]),
        target("non_library_docs", "test", true, true, &[]),
    ] {
        assert!(plan(&metadata(json!({}), vec![unsupported]), "core").is_err());
    }
    assert!(plan(&metadata(json!({}), vec![]), "core").is_err());
    assert!(plan(&data, "missing").is_err());
    assert!(
        plan(
            &metadata(
                json!({}),
                vec![
                    target("same", "test", true, false, &[]),
                    target("same", "test", true, false, &[])
                ]
            ),
            "core"
        )
        .is_err()
    );
}
