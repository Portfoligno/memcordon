#![cfg(feature = "test-fixtures")]

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use memcordon_testkit::{assert_stdout_empty, run_with_deadline};

fn require_backend() {
    let output = Command::new(env!("CARGO_BIN_EXE_memcordon"))
        .args(["probe", "--json"])
        .output()
        .expect("probe should run");
    let value: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("probe should return JSON");
    assert!(
        value
            .get("selected")
            .is_some_and(|selected| !selected.is_null()),
        "stress suite requires a supported backend"
    );
}

fn configured_iterations(name: &str) -> u32 {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../ci/policy.toml");
    let policy: toml::Value =
        toml::from_str(&fs::read_to_string(path).expect("CI policy should be readable"))
            .expect("CI policy should be valid TOML");
    policy["test"][name]
        .as_integer()
        .and_then(|value| value.try_into().ok())
        .filter(|value: &u32| *value > 0)
        .expect("deep iteration count should be positive")
}

fn reports_directory() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/ci/reports")
}

fn selected_seed() -> u64 {
    let configured = reports_directory().join("stress-seed.txt");
    if let Ok(text) = fs::read_to_string(configured) {
        return text
            .trim()
            .parse()
            .expect("configured stress seed should be an unsigned integer");
    }
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64
        ^ u64::from(std::process::id())
}

fn short_child_stress(iteration_key: &str) {
    require_backend();
    let iterations = configured_iterations(iteration_key);
    let started = Instant::now();
    let seed = selected_seed();
    let mut state = seed;
    eprintln!("stress seed: {seed}");
    for iteration in 0..iterations {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let code = match state % 3 {
            0 => 0,
            1 => 1,
            _ => 37,
        };
        let mut command = Command::new(env!("CARGO_BIN_EXE_memcordon"));
        command.args([
            "run",
            "--enforcement",
            if cfg!(target_os = "macos") {
                "watchdog"
            } else {
                "hard"
            },
            "--memory",
            "8GiB",
            "--",
            env!("CARGO_BIN_EXE_memcordon-test-fixture"),
            "exit",
            "--code",
            &code.to_string(),
        ]);
        let output = run_with_deadline(&mut command, Duration::from_secs(3))
            .unwrap_or_else(|error| panic!("iteration {iteration} failed: {error}"));
        assert_eq!(output.status.code(), Some(code), "iteration {iteration}");
        assert_stdout_empty(&output);
    }
    let mut tree = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    tree.args([
        "run",
        "--memory",
        "96MiB",
        "--",
        env!("CARGO_BIN_EXE_memcordon-test-fixture"),
        "spawn-tree",
        "--depth",
        "1",
        "--breadth",
        "4",
        "--leaf-mode",
        "allocate",
    ]);
    let tree_output = run_with_deadline(&mut tree, Duration::from_secs(15))
        .unwrap_or_else(|error| panic!("aggregate tree stress failed: {error}"));
    assert_eq!(tree_output.status.code(), Some(124));
    assert_stdout_empty(&tree_output);

    let mut burst = Command::new(env!("CARGO_BIN_EXE_memcordon"));
    burst.args([
        "run",
        "--memory",
        "256MiB",
        "--",
        env!("CARGO_BIN_EXE_memcordon-test-fixture"),
        "burst",
        "--bytes",
        "32MiB",
        "--hold",
        "10ms",
    ]);
    let burst_output = run_with_deadline(&mut burst, Duration::from_secs(5))
        .unwrap_or_else(|error| panic!("burst stress failed: {error}"));
    assert_eq!(burst_output.status.code(), Some(0));
    assert_stdout_empty(&burst_output);
    let elapsed = started.elapsed();
    let reports = reports_directory();
    fs::create_dir_all(&reports).expect("stress report directory should be creatable");
    let report = serde_json::json!({
        "schema": 1,
        "iteration_key": iteration_key,
        "iterations": iterations,
        "seed": seed,
        "elapsed_milliseconds": elapsed.as_millis(),
    });
    let mut bytes = serde_json::to_vec_pretty(&report).expect("stress report should serialize");
    bytes.push(b'\n');
    fs::write(reports.join(format!("stress-{iteration_key}.json")), bytes)
        .expect("stress report should be writable");
    eprintln!(
        "stress observation: iterations={iterations} elapsed_ms={} children_per_second={:.2}",
        elapsed.as_millis(),
        f64::from(iterations) / elapsed.as_secs_f64()
    );
    assert!(
        elapsed < Duration::from_secs(30 * 60),
        "stress budget exceeded"
    );
}

#[test]
#[ignore = "deep lifecycle stress"]
fn deep_short_children_are_bounded_reaped_and_observed() {
    short_child_stress("deep_short_child_iterations");
}

#[test]
#[ignore = "release lifecycle stress"]
fn release_short_children_are_bounded_reaped_and_observed() {
    short_child_stress("release_short_child_iterations");
}
