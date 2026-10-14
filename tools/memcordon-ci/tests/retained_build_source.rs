use memcordon_ci::retained_build_source::prepare_locked_source_tree;
use std::io::Write;

#[test]
fn fixed_retention_tree_accepts_all_five_original_files_exclusively() {
    let recipe = tempfile::tempdir().unwrap();
    let unrelated = recipe.path().join("existing-evidence");
    std::fs::write(&unrelated, b"unchanged").unwrap();
    prepare_locked_source_tree(recipe.path()).unwrap();
    for (relative, bytes) in [
        (
            "Cargo.toml",
            b"[package]\nname = \"fixture\"\nversion = \"0.0.0\"\n".as_slice(),
        ),
        ("Cargo.lock", b"version = 4\n".as_slice()),
        (
            "rust-toolchain.toml",
            b"[toolchain]\nchannel = \"1.97.1\"\n".as_slice(),
        ),
        ("src/main.rs", b"fn main() {}\n".as_slice()),
        (
            "tests/generated_child.rs",
            b"#[test]\nfn retained_fixture() {}\n".as_slice(),
        ),
    ] {
        let path = recipe.path().join("locked-source").join(relative);
        let mut held = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        held.write_all(bytes).unwrap();
        held.sync_all().unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), bytes);
        assert!(
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .is_err()
        );
    }
    assert!(prepare_locked_source_tree(recipe.path()).is_err());
    assert_eq!(std::fs::read(&unrelated).unwrap(), b"unchanged");
}

#[test]
fn retention_tree_never_recreates_recipe_or_adopts_existing_destinations() {
    let outer = tempfile::tempdir().unwrap();
    let absent = outer.path().join("absent-recipe");
    assert!(prepare_locked_source_tree(&absent).is_err());
    assert!(!absent.exists());
    let not_directory = outer.path().join("not-a-recipe-directory");
    std::fs::write(&not_directory, b"unchanged-prefix").unwrap();
    assert!(prepare_locked_source_tree(&not_directory).is_err());
    assert_eq!(std::fs::read(&not_directory).unwrap(), b"unchanged-prefix");
    for directory in [false, true] {
        let recipe = tempfile::tempdir().unwrap();
        let collision = recipe.path().join("locked-source");
        if directory {
            std::fs::create_dir(&collision).unwrap();
        } else {
            std::fs::write(&collision, b"existing-owner").unwrap();
        }
        assert!(prepare_locked_source_tree(recipe.path()).is_err());
        if directory {
            assert!(std::fs::read_dir(&collision).unwrap().next().is_none());
        } else {
            assert_eq!(std::fs::read(&collision).unwrap(), b"existing-owner");
        }
    }
}

#[cfg(unix)]
#[test]
fn retention_tree_refuses_symlink_without_writing_through_it() {
    let recipe = tempfile::tempdir().unwrap();
    let target = tempfile::tempdir().unwrap();
    let collision = recipe.path().join("locked-source");
    std::os::unix::fs::symlink(target.path(), &collision).unwrap();
    assert!(prepare_locked_source_tree(recipe.path()).is_err());
    assert!(std::fs::symlink_metadata(&collision).unwrap().is_symlink());
    assert!(std::fs::read_dir(target.path()).unwrap().next().is_none());
}
