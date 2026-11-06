#![cfg(feature = "test-support")]
use memcordon_platform::windows_private_fixture_binding::{
    PrivateFixtureAncestor, PrivateFixtureBinding, validate_declaration,
};
use std::path::PathBuf;

fn fixture() -> (PrivateFixtureBinding, Vec<PathBuf>) {
    let root = if cfg!(windows) {
        PathBuf::from("C:\\")
    } else {
        PathBuf::from("/")
    };
    let parent = root.join("owned");
    let directory = |path| PrivateFixtureAncestor {
        path,
        volume_serial: 7,
        file_index: 11,
        attributes: 0x10,
    };
    let fixture = parent.join("fixture.exe");
    let binding = PrivateFixtureBinding {
        revision: 1,
        fixture: fixture.clone(),
        volume_serial: 7,
        file_index: 42,
        attributes: 0x20,
        links: 1,
        bytes: 1234,
        sha256: "ab".repeat(32),
        native_path_utf16: r"\Device\Volume\owned\fixture.exe".encode_utf16().collect(),
        ancestors: vec![directory(root), directory(parent.clone())],
        local_directory: directory(parent.join("fixture.exe.local")),
    };
    let paths = vec![fixture, parent.join("fixture.exe.local/provider.dll")];
    (binding, paths)
}

#[test]
fn declarations_are_bounded_data_and_require_the_exact_experiment_target_set() {
    let (binding, paths) = fixture();
    binding.validate(&paths).unwrap();
    validate_declaration(true, &paths, Some(&binding)).unwrap();
    validate_declaration(false, &[], None).unwrap();
    assert!(validate_declaration(true, &paths, None).is_err());
    assert!(validate_declaration(false, &paths, Some(&binding)).is_err());
    assert!(validate_declaration(false, &paths, None).is_err());
    let mut reordered = paths.clone();
    reordered.swap(0, 1);
    assert!(binding.validate(&reordered).is_err());
    for target in [
        paths[1].join("nested.dll"),
        paths[0].with_file_name("other.exe"),
        PathBuf::from("relative.dll"),
    ] {
        let mut changed = paths.clone();
        changed[1] = target;
        assert!(binding.validate(&changed).is_err());
    }
    let mut duplicate = paths.clone();
    duplicate.push(paths[1].clone());
    assert!(binding.validate(&duplicate).is_err());
    let bytes = serde_json::to_vec(&binding).unwrap();
    let parsed: PrivateFixtureBinding = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(parsed, binding);
    let mut extra = serde_json::to_value(&binding).unwrap();
    extra["custody"] = true.into();
    assert!(serde_json::from_value::<PrivateFixtureBinding>(extra).is_err());
}

#[test]
fn malformed_identity_content_and_ancestry_cannot_enter_the_native_verifier() {
    let (original, paths) = fixture();
    for changed in [
        {
            let mut value = original.clone();
            value.revision = 2;
            value
        },
        {
            let mut value = original.clone();
            value.sha256 = "x".repeat(64);
            value
        },
        {
            let mut value = original.clone();
            value.bytes = 0;
            value
        },
        {
            let mut value = original.clone();
            value.links = 2;
            value
        },
        {
            let mut value = original.clone();
            value.attributes |= 0x400;
            value
        },
        {
            let mut value = original.clone();
            value.attributes |= 0x10;
            value
        },
        {
            let mut value = original.clone();
            value.native_path_utf16.push(0);
            value
        },
        {
            let mut value = original.clone();
            value.native_path_utf16 = vec![92; 2049];
            value
        },
        {
            let mut value = original.clone();
            value.ancestors.reverse();
            value
        },
        {
            let mut value = original.clone();
            value.ancestors[1].attributes |= 0x400;
            value
        },
        {
            let mut value = original.clone();
            value.ancestors[1].attributes = 0x20;
            value
        },
        {
            let mut value = original.clone();
            value.ancestors[1].path = paths[1].clone();
            value
        },
        {
            let mut value = original.clone();
            value.local_directory.path = paths[0].clone();
            value
        },
    ] {
        assert!(changed.validate(&paths).is_err());
    }
    // A well-formed identity/content substitution remains data: only actual
    // native handle/mapping comparisons may reject it or issue a capability.
    let mut substituted = original;
    substituted.file_index += 1;
    substituted.sha256 = "cd".repeat(32);
    substituted.validate(&paths).unwrap();
}
