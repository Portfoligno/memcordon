#[path = "../src/release/public_registry_location.rs"]
mod public_registry_location;

use std::fs;
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(0);

#[test]
fn registry_acquisition_rejects_ancestor_workspace_without_mutating_manifests() {
    let root = std::env::temp_dir().join(format!(
        "memcordon-registry-location-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).unwrap();
    public_registry_location::require_independent(&root).unwrap();
    let manifest = b"[workspace]\nmembers = []\nresolver = '2'\n";
    fs::write(root.join("Cargo.toml"), manifest).unwrap();
    let acquisition = root.join("target").join("registry-acquisition");
    fs::create_dir_all(&acquisition).unwrap();
    assert!(public_registry_location::require_independent(&acquisition).is_err());
    assert_eq!(fs::read(root.join("Cargo.toml")).unwrap(), manifest);
    assert!(!acquisition.join("Cargo.toml").exists());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn registry_acquisition_refuses_missing_original_directory() {
    let root = std::env::temp_dir().join(format!(
        "memcordon-registry-absent-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    assert!(public_registry_location::require_independent(&root).is_err());
}
