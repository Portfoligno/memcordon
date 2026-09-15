use memcordon_ci::api_surface::{
    Export, Surface, Tier, inspect_root, inspect_source, validate_surface,
};

fn surface(source: &str) -> Surface {
    Surface {
        package: "consumer".into(),
        root: "src/lib.rs".into(),
        fixtures: vec!["tests/stable_api.rs".into()],
        exports: inspect_source(source)
            .unwrap()
            .into_iter()
            .map(|fact| Export {
                fact,
                tier: Tier::StablePublic,
            })
            .collect(),
    }
}

#[test]
fn root_aliases_cfg_and_hidden_boundaries_are_distinct() {
    let original =
        "#[cfg(unix)] pub use inner::{Thing as PublicThing, other::Value}; pub(crate) mod private;";
    let declarations = surface(original);
    validate_surface(&declarations, &inspect_source(original).unwrap(), true).unwrap();
    for changed in [
        "#[cfg(windows)] pub use inner::{Thing as PublicThing, other::Value};",
        "#[cfg(unix)] pub use other::{Thing as PublicThing, other::Value};",
        "#[cfg(unix)] pub use inner::{Thing as Renamed, other::Value};",
        "#[cfg(unix)] #[doc(hidden)] pub use inner::{Thing as PublicThing, other::Value};",
        "#[cfg(unix)] pub use inner::{Thing as PublicThing, other::Value}; pub mod private;",
    ] {
        assert!(validate_surface(&declarations, &inspect_source(changed).unwrap(), true).is_err());
    }
}

#[test]
fn tier_changes_cannot_expose_tooling_or_ungated_tests_in_published_libraries() {
    let mut declarations = surface("pub struct Public;");
    let observed = inspect_source("pub struct Public;").unwrap();
    for tier in [Tier::ToolingOnly, Tier::TestOnly] {
        declarations.exports[0].tier = tier;
        assert!(validate_surface(&declarations, &observed, true).is_err());
    }
    declarations.exports[0].tier = Tier::StablePublic;
    declarations.fixtures.clear();
    assert!(validate_surface(&declarations, &observed, true).is_err());
    declarations.exports[0].tier = Tier::HiddenNativeHook;
    assert!(validate_surface(&declarations, &observed, true).is_err());
    for (source, accepted) in [
        ("#[cfg(feature = \"test-support\")] pub struct Test;", true),
        (
            "#[cfg(all(unix, feature = \"test-support\"))] pub struct Test;",
            true,
        ),
        (
            "#[cfg(any(unix, feature = \"test-support\"))] pub struct Test;",
            false,
        ),
        (
            "#[cfg(not(feature = \"test-support\"))] pub struct Test;",
            false,
        ),
    ] {
        let mut declarations = surface(source);
        declarations.exports[0].tier = Tier::TestOnly;
        assert_eq!(
            validate_surface(&declarations, &inspect_source(source).unwrap(), true).is_ok(),
            accepted
        );
    }
}

#[test]
fn local_glob_sources_are_bound_even_when_root_use_is_unchanged() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(
        directory.path().join("lib.rs"),
        "mod inner; pub use inner::*;",
    )
    .unwrap();
    std::fs::write(directory.path().join("inner.rs"), "pub struct Original;").unwrap();
    let before = inspect_root(directory.path(), "lib.rs").unwrap();
    assert!(before[0].glob_source_sha256.is_some());
    std::fs::write(
        directory.path().join("inner.rs"),
        "pub struct Original; pub struct Added;",
    )
    .unwrap();
    assert_ne!(before, inspect_root(directory.path(), "lib.rs").unwrap());
    assert!(inspect_root(directory.path(), "../lib.rs").is_err());
    std::fs::write(
        directory.path().join("alternate.rs"),
        "pub struct Redirected;",
    )
    .unwrap();
    for redirected in [
        "#[path = \"alternate.rs\"] mod inner; pub use inner::*;",
        "mod inner { pub struct Inline; } pub use inner::*;",
        "#[cfg(unix)] mod inner; pub use inner::*;",
        "#[cfg(unix)] mod inner; #[cfg(windows)] mod inner; pub use inner::*;",
    ] {
        std::fs::write(directory.path().join("lib.rs"), redirected).unwrap();
        assert!(inspect_root(directory.path(), "lib.rs").is_err());
    }
}

#[test]
fn duplicate_exports_and_unknown_tiers_fail_closed() {
    let mut declarations = surface("pub struct Public;");
    declarations.exports.push(declarations.exports[0].clone());
    assert!(
        validate_surface(
            &declarations,
            &inspect_source("pub struct Public;").unwrap(),
            true
        )
        .is_err()
    );
    assert!(
        toml::from_str::<memcordon_ci::api_surface::Catalog>(
            "schema = 1\nextra = true\nsurface = []\n"
        )
        .is_err()
    );
    assert!(serde_json::from_str::<Tier>("\"implicitly-public\"").is_err());
}

#[test]
fn checked_in_catalog_matches_all_cargo_library_roots_and_consumer_crates() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let metadata = memcordon_ci::policy::workspace_metadata(&root).unwrap();
    memcordon_ci::api_surface::validate(&root, &metadata).unwrap();
}
