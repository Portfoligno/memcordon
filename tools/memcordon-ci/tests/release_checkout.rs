use memcordon_ci::release::git::Git;
use std::fs;

#[test]
fn lf_checkout_matches_hermetic_git_without_accepting_source_or_index_edits() {
    #[cfg(unix)]
    let repository = tempfile::Builder::new()
        .prefix("memcordon-release-checkout-")
        .tempdir_in("/tmp")
        .unwrap();
    #[cfg(not(unix))]
    let repository = tempfile::Builder::new()
        .prefix("memcordon-release-checkout-")
        .tempdir()
        .unwrap();
    let git = Git::new(repository.path()).unwrap();
    git.text(["init", "--quiet"]).unwrap();
    git.text(["config", "user.name", "Release checkout fixture"])
        .unwrap();
    git.text(["config", "user.email", "fixture@example.invalid"])
        .unwrap();
    let tracked = repository.path().join("tracked-source");
    let original = b"first source line\nsecond source line\n";
    fs::write(&tracked, original).unwrap();
    git.text(["-c", "core.autocrlf=true", "add", "tracked-source"])
        .unwrap();
    git.text([
        "-c",
        "core.autocrlf=true",
        "commit",
        "--no-gpg-sign",
        "-m",
        "Fixture source",
    ])
    .unwrap();

    // Model Git for Windows checkout conversion without modifying ambient config.
    fs::remove_file(&tracked).unwrap();
    git.text([
        "-c",
        "core.autocrlf=true",
        "checkout-index",
        "--force",
        "--all",
    ])
    .unwrap();
    assert_eq!(
        fs::read(&tracked).unwrap(),
        b"first source line\r\nsecond source line\r\n"
    );
    assert!(git.require_clean().is_err());

    fs::remove_file(&tracked).unwrap();
    git.text([
        "-c",
        "core.autocrlf=false",
        "checkout-index",
        "--force",
        "--all",
    ])
    .unwrap();
    assert_eq!(fs::read(&tracked).unwrap(), original);
    git.require_clean().unwrap();

    fs::write(&tracked, b"changed source line\n").unwrap();
    assert!(git.require_clean().is_err());
    git.text(["add", "tracked-source"]).unwrap();
    assert!(
        git.text(["diff", "--", "tracked-source"])
            .unwrap()
            .is_empty()
    );
    assert!(git.require_clean().is_err());
    git.text(["checkout", "HEAD", "--", "tracked-source"])
        .unwrap();
    git.require_clean().unwrap();
}
