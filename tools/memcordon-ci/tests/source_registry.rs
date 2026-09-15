use std::collections::BTreeSet;

use memcordon_ci::source_registry::{Domain, Source, validate_records};

#[test]
fn workspace_source_registry_matches_observed_cargo_and_module_routes() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    memcordon_ci::source_registry::run(root).unwrap();
}

fn source() -> Source {
    Source {
        id: "core.policy".into(),
        path: "crates/core/src/policy.rs".into(),
        owner: "policy".into(),
        kind: "production".into(),
        visibility: "stable-public".into(),
        disposition: "retain".into(),
        protected_invariants: vec!["Invalid policies cannot authorize launch".into()],
        consumers: vec!["supervisor".into()],
        routes: vec!["module:crates/core/src/lib.rs:policy".into()],
        cfg: vec![],
        item_visibility: vec![],
        platforms: vec!["portable".into()],
        work_packages: vec!["GOV-01".into()],
        decision: "Keep policy validation independent of native authority".into(),
        replaces: vec![],
    }
}

#[test]
fn exact_membership_rejects_missing_stale_and_duplicate_sources() {
    let source = source();
    let inventory = BTreeSet::from([source.path.clone()]);
    validate_records(std::slice::from_ref(&source), &inventory).unwrap();
    assert!(validate_records(&[], &inventory).is_err());
    assert!(validate_records(std::slice::from_ref(&source), &BTreeSet::new()).is_err());
    assert!(validate_records(&[source.clone(), source.clone()], &inventory).is_err());
    let mut duplicate = source.clone();
    duplicate.path = "crates/core/src/another.rs".into();
    let both = BTreeSet::from([source.path.clone(), duplicate.path.clone()]);
    assert!(validate_records(&[source, duplicate], &both).is_err());
}

#[test]
fn declarations_reject_unknown_fields_and_unknown_tiers() {
    let domain = Domain {
        schema: 1,
        source: vec![source()],
    };
    let mut document = toml::to_string(&domain).unwrap();
    document.push_str("invented_authority = true\n");
    assert!(toml::from_str::<Domain>(&document).is_err());
    let mut source = source();
    let inventory = BTreeSet::from([source.path.clone()]);
    source.visibility = "secretly-public".into();
    assert!(validate_records(&[source], &inventory).is_err());
}

#[test]
fn declarations_require_reviewable_invariants_routes_and_safe_paths() {
    let original = source();
    let inventory = BTreeSet::from([original.path.clone()]);
    let mut no_invariant = original.clone();
    no_invariant.protected_invariants.clear();
    assert!(validate_records(&[no_invariant], &inventory).is_err());
    let mut no_route = original.clone();
    no_route.routes.clear();
    assert!(validate_records(&[no_route], &inventory).is_err());
    let mut duplicate_route = original.clone();
    duplicate_route.routes.push(original.routes[0].clone());
    assert!(validate_records(&[duplicate_route], &inventory).is_err());
    let mut unsafe_path = original;
    unsafe_path.path = "crates/../outside.rs".into();
    let inventory = BTreeSet::from([unsafe_path.path.clone()]);
    assert!(validate_records(&[unsafe_path], &inventory).is_err());
}

#[test]
fn migration_cannot_replace_itself_or_an_active_identity() {
    let original = source();
    let inventory = BTreeSet::from([original.path.clone()]);
    let mut self_replacement = original.clone();
    self_replacement.replaces.push(original.id.clone());
    assert!(validate_records(&[self_replacement], &inventory).is_err());
    let mut empty_replacement = original.clone();
    empty_replacement.replaces.push(" ".into());
    assert!(validate_records(&[empty_replacement], &inventory).is_err());
    let mut replacement = original.clone();
    replacement.id = "core.new".into();
    replacement.path = "crates/core/src/new.rs".into();
    replacement.replaces.push(original.id.clone());
    let inventory = BTreeSet::from([original.path.clone(), replacement.path.clone()]);
    assert!(validate_records(&[original, replacement], &inventory).is_err());
}

#[test]
fn history_requires_explicit_retirement_and_preserves_move_identity() {
    use memcordon_ci::source_registry::validate_history;
    let history = "schema = 1\n[[identity]]\nid = 'core.policy'\noriginal_path = 'crates/core/src/policy.rs'\n";
    let mut moved = source();
    moved.path = "crates/core/src/policy/mod.rs".into();
    validate_history(history, &[moved.clone()]).unwrap();
    assert!(validate_history(history, &[]).is_err());
    moved.id = "core.renamed-without-migration".into();
    assert!(validate_history(history, &[moved]).is_err());
    let retired = [history, "[[retired]]\nid = 'core.policy'\nreason = 'Superseded by a separately reviewed contract.'\n"].concat();
    validate_history(&retired, &[]).unwrap();
    assert!(validate_history(&retired, &[source()]).is_err());
    let mut invalid_replacement = source();
    invalid_replacement.replaces.push("never-existed".into());
    assert!(validate_history(history, &[invalid_replacement]).is_err());
}

#[test]
fn syntax_surface_detects_cfg_and_visibility_mutations_in_nested_modules() {
    use memcordon_ci::source_registry::rust_surface;
    let original = "#[cfg(windows)] mod native { #[cfg_attr(test, allow(dead_code))] pub(crate) struct Handle; }";
    let expected = rust_surface(original).unwrap();
    assert_eq!(expected.0.len(), 2);
    assert!(
        expected
            .1
            .iter()
            .any(|item| item == "mod:native#1/struct:Handle#1:pub(crate)")
    );
    assert_ne!(
        expected,
        rust_surface(&original.replace("pub(crate)", "pub")).unwrap()
    );
    assert_ne!(
        expected,
        rust_surface(&original.replace("cfg(windows)", "cfg(unix)")).unwrap()
    );
    assert_ne!(
        expected,
        rust_surface(&original.replace("#[cfg_attr(test, allow(dead_code))]", "")).unwrap()
    );
}

#[test]
fn syntax_gates_and_visibility_are_bound_to_their_qualified_owner() {
    use memcordon_ci::source_registry::rust_surface;
    let guarded = "#[cfg(feature=\"test-support\")] fn privileged() {} fn unrelated() {}";
    let moved = "fn privileged() {} #[cfg(feature=\"test-support\")] fn unrelated() {}";
    assert_ne!(rust_surface(guarded).unwrap(), rust_surface(moved).unwrap());
    let body =
        "fn privileged() { #[cfg(feature=\"test-support\")] let ignored = 1; } fn unrelated() {}";
    assert_ne!(rust_surface(guarded).unwrap(), rust_surface(body).unwrap());
    let original = "mod a { pub fn f() {} } mod b { fn f() {} }";
    let swapped = "mod a { fn f() {} } mod b { pub fn f() {} }";
    assert_ne!(
        rust_surface(original).unwrap(),
        rust_surface(swapped).unwrap()
    );
    let alternatives = "#[cfg(unix)] pub fn f() {} #[cfg(windows)] fn f() {}";
    let swapped_alternatives = "#[cfg(unix)] fn f() {} #[cfg(windows)] pub fn f() {}";
    assert_ne!(
        rust_surface(alternatives).unwrap(),
        rust_surface(swapped_alternatives).unwrap()
    );
    for source in [
        "use crate::Hidden;",
        "impl Owner { fn method() {} }",
        "struct Owner { field: u8 }",
    ] {
        let public = if source.starts_with("use") {
            source.replacen("use", "pub use", 1)
        } else if source.starts_with("impl") {
            source.replacen("fn", "pub fn", 1)
        } else {
            source.replacen("field", "pub field", 1)
        };
        assert_ne!(
            rust_surface(source).unwrap(),
            rust_surface(&public).unwrap()
        );
    }
}
