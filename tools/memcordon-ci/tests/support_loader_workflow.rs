use memcordon_ci::{config, policy};
use serde_yaml::Value;
use std::path::{Path, PathBuf};

fn check(value: &Value) -> memcordon_ci::Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    policy::validate_workflow_bytes(
        &root,
        Path::new(".github/workflows/release.yml"),
        serde_yaml::to_string(value)?.as_bytes(),
        &config::policy(&root)?,
    )
}

#[test]
fn support_diagnostic_requires_separate_settled_producer_and_non_authority_artifacts() {
    let baseline: Value =
        serde_yaml::from_str(include_str!("../../../.github/workflows/release.yml")).unwrap();
    check(&baseline).unwrap();
    for job in ["native-windows-x64", "native-windows-arm64"] {
        let steps = baseline["jobs"][job]["steps"].as_sequence().unwrap();
        let find = |id: &str| {
            let matches: Vec<_> = steps
                .iter()
                .enumerate()
                .filter(|(_, step)| step["id"].as_str() == Some(id))
                .map(|(index, _)| index)
                .collect();
            assert_eq!(matches.len(), 1);
            matches[0]
        };
        let run = find("support_loader_diagnostic");
        let cleanup = find("support_loader_diagnostic_cleanup");
        let acceptance = find("native_readiness");
        let payload = find("payload");
        let upload = steps
            .iter()
            .position(|step| {
                step["with"]["path"].as_str()
                    == Some(".release/support-loader-diagnostic/diagnostic-artifacts")
            })
            .unwrap();
        let mutations = [
            (acceptance, "continue-on-error", Value::Bool(true)),
            (payload, "continue-on-error", Value::Bool(true)),
            (
                run,
                "if",
                Value::String("always() && runner.os == 'Windows'".into()),
            ),
            (run, "continue-on-error", Value::Bool(false)),
            (
                cleanup,
                "if",
                Value::String("runner.os == 'Windows'".into()),
            ),
            (cleanup, "run", Value::String("echo skipped".into())),
            (upload, "if", Value::String("success()".into())),
        ];
        for (index, field, replacement) in mutations {
            let mut changed = baseline.clone();
            changed["jobs"][job]["steps"][index][field] = replacement;
            assert_ne!(changed, baseline);
            assert!(check(&changed).is_err(), "accepted {job}/{index}/{field}");
        }
        let mut changed = baseline.clone();
        changed["jobs"]["candidate-windows-x64-native"]["steps"]
            .as_sequence_mut()
            .unwrap()
            .push(steps[run].clone());
        assert_ne!(changed, baseline);
        assert!(
            check(&changed).is_err(),
            "optional diagnostic leaked into ordinary consumer context"
        );
        let mut changed = baseline.clone();
        changed["jobs"][job]["steps"][upload]["with"]["path"] =
            Value::String(".release/support-loader-diagnostic".into());
        assert_ne!(changed, baseline);
        assert!(check(&changed).is_err());
        let mut changed = baseline.clone();
        changed["jobs"][job]["steps"]
            .as_sequence_mut()
            .unwrap()
            .remove(cleanup);
        assert!(check(&changed).is_err());
        for (index, step) in steps.iter().enumerate() {
            if step["uses"].as_str()
                == Some("actions/cache/save@55cc8345863c7cc4c66a329aec7e433d2d1c52a9")
            {
                let mut changed = baseline.clone();
                let condition = step["if"].as_str().unwrap();
                let altered = condition.replace(" && (steps.support_loader_diagnostic.outputs.diagnostic-started != 'true' || steps.support_loader_diagnostic_cleanup.outputs.cache-quiescent == 'true')", "");
                assert_ne!(condition, altered);
                changed["jobs"][job]["steps"][index]["if"] = Value::String(altered);
                assert!(check(&changed).is_err());
            }
        }
    }
}
