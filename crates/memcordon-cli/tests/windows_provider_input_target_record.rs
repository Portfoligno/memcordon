#[path = "../src/bin/consumer_readiness_windows/provider_input_target_record.rs"]
mod record;

use record::{Context, reject};
use std::path::PathBuf;

fn root() -> PathBuf {
    if cfg!(windows) {
        PathBuf::from(r"C:\owned")
    } else {
        PathBuf::from("/owned")
    }
}

#[test]
fn exact_fixture_and_immediate_leaves_preserve_all_guard_refusals() {
    let parent = root();
    let executable = parent.join("fixture.exe");
    let directory = parent.join("fixture.exe.local");
    let output = root().with_file_name("output");
    let valid = vec![executable.clone(), directory.join("provider.dll")];
    let evaluate = |paths: &[PathBuf], output: &std::path::Path| {
        reject(&Context {
            paths,
            fixture: &executable,
            output_root: output,
            parent: &parent,
            directory: &directory,
            peer: true,
            file_layout: false,
        })
    };
    assert!(evaluate(&valid, &output).is_none());
    let cases = [
        (vec![], "target-count-below-two", None),
        (
            vec![executable.clone(); 10],
            "target-count-above-nine",
            None,
        ),
        (
            vec![parent.join("other.exe"), valid[1].clone()],
            "verified-fixture-not-in-declared-targets",
            None,
        ),
        (
            vec![executable.clone(), PathBuf::from("relative.dll")],
            "target-not-absolute",
            Some(1),
        ),
        (
            vec![
                executable.clone(),
                directory.join("..").join("provider.dll"),
            ],
            "target-has-dot-component",
            Some(1),
        ),
        (
            vec![
                executable.clone(),
                directory.join("nested").join("provider.dll"),
            ],
            "target-not-immediate-current-local-leaf",
            Some(1),
        ),
        (
            vec![executable.clone(), valid[1].clone(), valid[1].clone()],
            "duplicate-target",
            Some(2),
        ),
    ];
    for (paths, expected, index) in cases {
        let refusal = evaluate(&paths, &output).unwrap();
        assert_eq!(refusal.predicate, expected);
        assert_eq!(refusal.target_index, index);
        assert_eq!(
            refusal.primary,
            if expected == "duplicate-target" {
                "duplicate private mutation target"
            } else {
                "mutation targets are not the exact private fixture and immediate .local leaves"
            }
        );
    }
    for (output, expected) in [
        (PathBuf::from("relative"), "output-not-absolute"),
        (
            directory.join("out"),
            "output-under-current-local-directory",
        ),
        (parent.join("out"), "output-under-current-executable-parent"),
    ] {
        assert_eq!(evaluate(&valid, &output).unwrap().predicate, expected);
    }
    let context = Context {
        paths: &valid,
        fixture: &executable,
        output_root: &output,
        parent: &parent,
        directory: &directory,
        peer: true,
        file_layout: false,
    };
    assert!(context.peer);
    assert!(record::output_separate(&context));
    let mut siblings = vec![executable.clone(), directory.clone()];
    siblings.extend((0..8).map(|index| parent.join(format!("provider-{index}.dll"))));
    let file_context = Context {
        paths: &siblings,
        directory: &parent,
        file_layout: true,
        ..context
    };
    assert!(reject(&file_context).is_none());
    assert!(record::output_separate(&file_context));
    assert_eq!(
        reject(&Context {
            paths: &siblings[..2],
            ..file_context
        })
        .unwrap()
        .predicate,
        "target-count-below-three"
    );
    assert_eq!(
        reject(&Context {
            file_layout: false,
            ..file_context
        })
        .unwrap()
        .predicate,
        "target-count-above-nine"
    );
}

#[test]
fn path_evidence_preserves_exact_utf16_and_bounds_long_or_unusual_forms() {
    let observed = r"\\?\C:\Owned\fixture.exe"
        .encode_utf16()
        .collect::<Vec<_>>();
    let declared = r"C:\owned\fixture.exe".encode_utf16().collect::<Vec<_>>();
    let a = record::path_record(observed.iter().copied(), true);
    let b = record::path_record(declared.iter().copied(), true);
    assert_eq!(a["utf16_prefix"], serde_json::json!(observed));
    assert_ne!(a["sha256"], b["sha256"]);
    assert_eq!(a["extended_length_prefix_observed"], true);
    assert_eq!(a["case_or_prefix_normalization_performed"], false);
    let long = record::path_record(std::iter::repeat_n(u16::MAX, 32768), true);
    assert_eq!(long["utf16_units"], 32768);
    assert_eq!(long["utf16_prefix"].as_array().unwrap().len(), 256);
    assert_eq!(long["utf16_truncated"], true);
    assert!(serde_json::to_vec(&long).unwrap().len() < 2048);
    assert!(serde_json::to_vec(&long).unwrap().len() <= record::RECORD_BYTES);
    let hashed = record::path_record(declared.iter().copied(), false);
    assert!(hashed.get("utf16_prefix").is_none());
}
