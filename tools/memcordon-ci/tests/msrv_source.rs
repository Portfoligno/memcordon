use std::path::Path;

use syn::visit::Visit;

#[derive(Default)]
struct LetChainVisitor {
    count: usize,
}

impl<'ast> Visit<'ast> for LetChainVisitor {
    fn visit_expr_binary(&mut self, expression: &'ast syn::ExprBinary) {
        if matches!(expression.op, syn::BinOp::And(_) | syn::BinOp::Or(_))
            && (contains_let(&expression.left) || contains_let(&expression.right))
        {
            self.count += 1;
        }
        syn::visit::visit_expr_binary(self, expression);
    }
}

fn contains_let(expression: &syn::Expr) -> bool {
    match expression {
        syn::Expr::Let(_) => true,
        syn::Expr::Binary(binary)
            if matches!(binary.op, syn::BinOp::And(_) | syn::BinOp::Or(_)) =>
        {
            contains_let(&binary.left) || contains_let(&binary.right)
        }
        syn::Expr::Group(group) => contains_let(&group.expr),
        syn::Expr::Paren(paren) => contains_let(&paren.expr),
        _ => false,
    }
}

fn let_chain_count(source: &str) -> usize {
    let syntax = syn::parse_file(source).expect("MSRV source fixture must parse as Rust");
    let mut visitor = LetChainVisitor::default();
    visitor.visit_file(&syntax);
    visitor.count
}

#[test]
fn detector_recognizes_both_let_chain_shapes() {
    let source = r#"
        fn check(first: Option<u8>, second: Result<u8, ()>) {
            if let Some(value) = first && value > 0 {}
            if true && let Ok(value) = second && value > 0 {}
        }
    "#;

    assert_eq!(let_chain_count(source), 3);
}

#[test]
fn production_sources_do_not_use_post_msrv_let_chains() {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates = manifest.join("../../crates");
    let mut checked = 0;

    for entry in walkdir::WalkDir::new(&crates) {
        let entry = entry.expect("production source tree must be readable");
        if !entry.file_type().is_file() || entry.path().extension().is_none_or(|ext| ext != "rs") {
            continue;
        }
        let source = std::fs::read_to_string(entry.path())
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", entry.path().display()));
        assert_eq!(
            let_chain_count(&source),
            0,
            "production Rust source exceeds the declared Rust 1.85 MSRV: {}",
            entry.path().display()
        );
        checked += 1;
    }

    assert!(checked > 0, "production Rust source tree must not be empty");
}
