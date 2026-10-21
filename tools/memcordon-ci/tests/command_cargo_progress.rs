#![cfg(target_os = "macos")]

use memcordon_ci::command::{CiPhase, CommandSpec};
use std::{fs, process::Command, time::Duration};

#[test]
fn owned_native_compile_observes_bounded_redacted_cargo_progress() {
    let root = tempfile::tempdir().unwrap();
    let source = root.path().join("progress_fixture.rs");
    let executable = root.path().join("progress-fixture");
    fs::write(
        &source,
        r#"fn main() {
        eprintln!("    Blocking waiting for file lock on package cache");
        eprintln!("   Compiling visible_fixture");
        eprintln!("   Compiling password=must_not_be_retained");
        eprintln!("    Finished release fixture");
    }
"#,
    )
    .unwrap();
    let compiler = Command::new("rustc")
        .arg("--edition=2024")
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        compiler.status.success(),
        "{}",
        String::from_utf8_lossy(&compiler.stderr)
    );
    CommandSpec::cargo(&executable, root.path(), "stable", Duration::from_secs(10))
        .args(["test", "--no-run"])
        .phase(CiPhase::NativeCompile)
        .run_owned()
        .into_result()
        .unwrap();
    let reports = fs::read_dir(root.path().join("target/ci/reports/execution"))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert_eq!(reports.len(), 1);
    let report: serde_json::Value =
        serde_json::from_slice(&fs::read(reports[0].path().join("native-compile.json")).unwrap())
            .unwrap();
    let progress = &report["cargo-progress"];
    assert_eq!(progress["first_lock"]["kind"], "lock-wait");
    assert_eq!(
        progress["first_compile"]["text"],
        "Compiling visible_fixture"
    );
    assert_eq!(progress["last_progress"]["kind"], "finished");
    assert_eq!(progress["records"].as_array().unwrap().len(), 3);
    assert_eq!(progress["omitted_chunks"], 0);
    assert!(
        !serde_json::to_string(progress)
            .unwrap()
            .contains("must_not_be_retained")
    );
    assert_eq!(report["state"], "completed");
    assert_eq!(report["cleanup"], "complete");
}
