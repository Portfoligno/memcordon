use std::collections::{BTreeMap, BTreeSet};

use memcordon_ci::boundary_metrics::{analyze_files, analyze_source};

#[test]
fn syntax_distinguishes_visibility_cfg_and_real_unsafe_from_comments() {
    let metrics = analyze_source(
        r#"
        // unsafe { bogus() }
        pub fn visible() { hidden(); }
        pub(crate) unsafe fn restricted() { unsafe { hidden() }; }
        #[cfg(any())] fn hidden() {}
        #[test] fn test_case() { visible(); }
        "#,
    )
    .unwrap();
    assert_eq!(metrics.items, 4);
    assert_eq!(metrics.public_items, 1);
    assert_eq!(metrics.restricted_items, 1);
    assert_eq!(metrics.private_items, 2);
    assert_eq!(metrics.unsafe_blocks, 1);
    assert_eq!(metrics.unsafe_functions, 1);
    assert_eq!(metrics.cfg_regions, 1);
    assert!(
        metrics
            .test_functions
            .iter()
            .any(|identity| metrics.function_names[identity] == "test_case")
    );
    assert!(analyze_source("fn broken(").is_err());
}

#[test]
fn coupling_is_deterministic_and_ambiguous_names_do_not_create_edges() {
    let sources = BTreeMap::from([
        (
            "src/alpha.rs".into(),
            "fn one() { two(); } fn two() {} fn isolated() {}".into(),
        ),
        (
            "tests/cases.rs".into(),
            "use crate::{alpha::one, duplicate::*}; #[test] fn checks() { one(); }".into(),
        ),
        ("src/left/duplicate.rs".into(), "fn duplicate() {}".into()),
        ("src/right/duplicate.rs".into(), "fn duplicate() {}".into()),
    ]);
    let history = vec![BTreeSet::from([
        "src/alpha.rs".into(),
        "tests/cases.rs".into(),
    ])];
    let files = analyze_files(&sources, &history).unwrap();
    let alpha = files
        .iter()
        .find(|file| file.path == "src/alpha.rs")
        .unwrap();
    assert_eq!(
        alpha.approximate_test_references,
        BTreeSet::from(["tests/cases.rs".into()])
    );
    assert_eq!(alpha.cochanges["tests/cases.rs"], 1);
    assert!(
        alpha
            .approximate_call_clusters
            .contains(&BTreeSet::from(["one#0".into(), "two#1".into()]))
    );
    assert!(
        alpha
            .approximate_call_clusters
            .contains(&BTreeSet::from(["isolated#2".into()]))
    );
    let cases = files
        .iter()
        .find(|file| file.path == "tests/cases.rs")
        .unwrap();
    assert_eq!(
        cases.approximate_imports,
        BTreeSet::from(["src/alpha.rs".into()])
    );
    assert_eq!(
        serde_json::to_string(&files).unwrap(),
        serde_json::to_string(&analyze_files(&sources, &history).unwrap()).unwrap()
    );
}

#[test]
fn cfg_alternatives_remain_distinct_and_never_form_a_false_call_bridge() {
    let sources = BTreeMap::from([(
        "src/alternative.rs".into(),
        r#"
        #[cfg(unix)] fn chosen() { left(); }
        #[cfg(windows)] fn chosen() { right(); }
        fn left() {}
        fn right() {}
        fn caller() { chosen(); }
    "#
        .into(),
    )]);
    let files = analyze_files(&sources, &[]).unwrap();
    let file = &files[0];
    assert_eq!(file.syntax.functions.len(), 5);
    let chosen: Vec<_> = file
        .syntax
        .function_names
        .iter()
        .filter(|(_, name)| name.as_str() == "chosen")
        .map(|(id, _)| id)
        .collect();
    assert_eq!(chosen.len(), 2);
    assert_ne!(file.syntax.calls[chosen[0]], file.syntax.calls[chosen[1]]);
    assert!(
        file.approximate_call_clusters
            .iter()
            .all(|cluster| !(cluster.contains(chosen[0]) && cluster.contains(chosen[1])))
    );
    let caller = file
        .syntax
        .function_names
        .iter()
        .find(|(_, name)| name.as_str() == "caller")
        .unwrap()
        .0;
    assert!(
        file.approximate_call_clusters
            .contains(&BTreeSet::from([caller.clone()]))
    );
}

#[test]
fn nested_helpers_keep_their_enclosing_impl_method_and_calls() {
    let metrics = analyze_source(
        r#"
        struct S;
        impl S {
            fn a() { fn helper() { left(); } }
            fn b() { fn helper() { right(); } }
        }
    "#,
    )
    .unwrap();
    assert_eq!(metrics.functions.len(), 4);
    let helper_a = metrics
        .function_names
        .iter()
        .find(|(_, name)| name.ends_with("::a::helper"))
        .unwrap()
        .0;
    let helper_b = metrics
        .function_names
        .iter()
        .find(|(_, name)| name.ends_with("::b::helper"))
        .unwrap()
        .0;
    assert_ne!(helper_a, helper_b);
    assert_eq!(metrics.calls[helper_a], BTreeSet::from(["left".into()]));
    assert_eq!(metrics.calls[helper_b], BTreeSet::from(["right".into()]));
}

#[test]
fn unsafe_signatures_include_trait_and_foreign_declarations() {
    let metrics = analyze_source(
        r#"
        trait T { unsafe fn trait_method(); }
        unsafe extern "C" { unsafe fn foreign_function(); safe fn safe_function(); }
        unsafe fn free_function() {}
        struct S;
        impl S { unsafe fn method() {} }
    "#,
    )
    .unwrap();
    assert_eq!(metrics.unsafe_functions, 4);
    assert_eq!(metrics.unsafe_blocks, 0);
}
