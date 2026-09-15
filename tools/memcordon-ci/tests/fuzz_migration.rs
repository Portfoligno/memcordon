use std::ffi::OsString;
use std::path::Path;

use memcordon_ci::fuzz_migration::{CANONICAL, DUPLICATE, minimize, prepare, replay};
use memcordon_ci::fuzz_targets::CharterRegistry;

fn registry() -> CharterRegistry {
    CharterRegistry::load(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .as_path(),
    )
    .unwrap()
}

#[test]
fn migration_preserves_inputs_and_distinguishes_crashes_from_reports() {
    let temporary = tempfile::tempdir().unwrap();
    let canonical_root = temporary.path().canonicalize().unwrap();
    let root = canonical_root.as_path();
    let registry = registry();
    let canonical = registry
        .targets
        .iter()
        .find(|target| target.bin == CANONICAL)
        .unwrap();
    let duplicate = registry
        .targets
        .iter()
        .find(|target| target.bin == DUPLICATE)
        .unwrap();
    let seed = root.join(&canonical.seed_directory);
    std::fs::create_dir_all(&seed).unwrap();
    std::fs::write(seed.join("accepted"), b"first\n").unwrap();
    let old_corpus = root.join("fuzz/corpus").join(DUPLICATE);
    std::fs::create_dir_all(&old_corpus).unwrap();
    std::fs::write(old_corpus.join("same"), b"first\n").unwrap();
    std::fs::write(old_corpus.join("unique"), b"second\n").unwrap();
    let old_crashes = root.join("fuzz/artifacts").join(DUPLICATE);
    std::fs::create_dir_all(&old_crashes).unwrap();
    std::fs::write(old_crashes.join("crash-original"), b"third\n").unwrap();
    let stable = canonical.artifact_directory(root);
    std::fs::create_dir_all(&stable).unwrap();
    std::fs::write(
        stable.join("evidence.json"),
        b"this report is not an input\n",
    )
    .unwrap();
    let historical = b"fourth\n";
    use sha2::Digest;
    let historical_name = hex::encode(sha2::Sha256::digest(historical));
    std::fs::write(stable.join(&historical_name), historical).unwrap();
    let staging = root.join("staging");
    let inputs = prepare(root, &staging, [canonical, duplicate]).unwrap();
    assert_eq!(inputs.corpus.len(), 2);
    assert_eq!(inputs.crashes.len(), 2);
    assert_eq!(
        std::fs::read_dir(staging.join("minimized"))
            .unwrap()
            .count(),
        4
    );
    // Model a destructive minimizer on its disposable copy. Originals remain.
    let copied = staging.join("minimized").join(&inputs.corpus[0].sha256);
    std::fs::write(copied, b"minimizer replacement\n").unwrap();
    assert_eq!(
        std::fs::read(old_corpus.join("unique")).unwrap(),
        b"second\n"
    );
    assert_eq!(
        std::fs::read(old_crashes.join("crash-original")).unwrap(),
        b"third\n"
    );
    assert_eq!(
        std::fs::read(stable.join(historical_name)).unwrap(),
        historical
    );
    for input in &inputs.corpus {
        assert_ne!(
            std::fs::read(staging.join("original-corpus").join(&input.sha256)).unwrap(),
            b"minimizer replacement\n"
        );
    }
}

#[test]
fn migration_refuses_empty_or_incompatible_inputs() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    let registry = registry();
    let canonical = registry
        .targets
        .iter()
        .find(|target| target.bin == CANONICAL)
        .unwrap();
    let duplicate = registry
        .targets
        .iter()
        .find(|target| target.bin == DUPLICATE)
        .unwrap();
    assert!(
        prepare(&root, &root.join("empty"), [canonical, duplicate])
            .unwrap_err()
            .to_string()
            .contains("no corpus inputs")
    );
    let mut incompatible = duplicate.clone();
    incompatible.max_input_bytes += 1;
    assert!(
        prepare(
            &root,
            &root.join("incompatible"),
            [canonical, &incompatible]
        )
        .unwrap_err()
        .to_string()
        .contains("input bounds disagree")
    );
}

#[test]
fn replay_and_cmin_preserve_native_argument_boundaries() {
    let entry = memcordon_ci::fuzz_targets::CorpusEntry {
        sha256: "input name with spaces".into(),
        bytes: 1,
    };
    let directory = Path::new("staging with spaces");
    let replay = replay(DUPLICATE, directory, &entry);
    assert_eq!(
        replay.arguments,
        [
            OsString::from("fuzz"),
            "run".into(),
            DUPLICATE.into(),
            directory.join(&entry.sha256).into_os_string(),
            "--".into(),
            "-runs=1".into(),
        ]
    );
    let minimize = minimize(directory);
    assert_eq!(
        minimize.arguments,
        [
            OsString::from("fuzz"),
            "cmin".into(),
            CANONICAL.into(),
            directory.as_os_str().into()
        ]
    );
    assert!(!minimize.arguments.iter().any(|argument| argument == "--"));
}

#[test]
fn ordered_proof_replays_original_crashes_again_after_minimization() {
    use memcordon_ci::fuzz_migration::{Inputs, verify};
    use memcordon_ci::fuzz_targets::merge_corpora;
    let temporary = tempfile::tempdir().unwrap();
    let staging = temporary.path().canonicalize().unwrap();
    let seeds = staging.join("seeds");
    let crashes = staging.join("crashes");
    std::fs::create_dir(&seeds).unwrap();
    std::fs::create_dir(&crashes).unwrap();
    std::fs::write(seeds.join("seed"), b"ordinary\n").unwrap();
    std::fs::write(crashes.join("crash"), b"historical crash\n").unwrap();
    let inputs = Inputs {
        corpus: merge_corpora(
            std::slice::from_ref(&seeds),
            &staging.join("original-corpus"),
            4096,
        )
        .unwrap(),
        crashes: merge_corpora(&[crashes], &staging.join("original-crashes"), 4096).unwrap(),
        searched_paths: Vec::new(),
    };
    // A stub minimizer retains only the ordinary seed. The production driver
    // must still replay the original crash afterward, independently of cmin.
    let mut stages = Vec::new();
    let minimized = verify(&staging, &inputs, 4096, |invocation| {
        if invocation.phase == "cmin" {
            merge_corpora(
                std::slice::from_ref(&seeds),
                &staging.join("minimized"),
                4096,
            )?;
        }
        stages.push(invocation);
        Ok(())
    })
    .unwrap();
    assert_eq!(minimized.len(), 1);
    let cmin = stages
        .iter()
        .position(|stage| stage.phase == "cmin")
        .unwrap();
    for bin in [CANONICAL, DUPLICATE] {
        for input in inputs.corpus.iter().chain(&inputs.crashes) {
            assert!(stages[..cmin].iter().any(|stage| {
                stage
                    .arguments
                    .get(2)
                    .is_some_and(|argument| argument == bin)
                    && stage.input_sha256.as_ref() == Some(&input.sha256)
            }));
        }
    }
    assert!(
        stages[cmin + 1..]
            .iter()
            .all(|stage| stage.arguments[2] == CANONICAL)
    );
    assert!(
        stages[cmin + 1..]
            .iter()
            .any(|stage| stage.input_sha256.as_ref() == Some(&inputs.crashes[0].sha256))
    );
    // Every unsuccessful stage stops immediately; no later cmin/replay can
    // transform a failure into a passing prerequisite.
    for failed in 0..stages.len() {
        let mut visited = 0;
        let error = verify(&staging, &inputs, 4096, |_| {
            let current = visited;
            visited += 1;
            if current == failed {
                Err(memcordon_ci::CiError::Message(
                    "injected native stage failure".into(),
                ))
            } else {
                Ok(())
            }
        })
        .unwrap_err();
        assert!(error.to_string().contains("injected native stage failure"));
        assert_eq!(visited, failed + 1);
    }
}
