use syn::{Expr, Pat, Stmt, visit::Visit};

#[derive(Default)]
struct Calls(Vec<syn::ExprCall>);
impl<'ast> Visit<'ast> for Calls {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        self.0.push(call.clone());
        syn::visit::visit_expr_call(self, call);
    }
}
fn target(call: &syn::ExprCall, name: &str) -> bool {
    matches!(&*call.func, Expr::Path(path) if path.path.segments.last().is_some_and(|segment| segment.ident == name))
}
fn calls(block: &syn::Block) -> Vec<syn::ExprCall> {
    let mut visitor = Calls::default();
    visitor.visit_block(block);
    visitor.0
}
fn measured_binding(statement: &Stmt) -> bool {
    matches!(statement, Stmt::Local(local) if matches!(&local.pat, Pat::Type(typed) if matches!(&*typed.pat, Pat::Ident(name) if name.ident == "measured")) && local.init.as_ref().is_some_and(|init| matches!(&*init.expr, Expr::Path(path) if path.path.is_ident("OpenEventW"))))
}

#[test]
fn call_markers_surround_one_typed_call_only_in_the_explicit_replay_branch() {
    let syntax = syn::parse_file(include_str!("../../../crates/memcordon-cli/src/bin/consumer_readiness_windows/namespace_primary_worker.rs")).unwrap();
    let function = syntax
        .items
        .iter()
        .find_map(|item| match item {
            syn::Item::Fn(function) if function.sig.ident == "run_request" => Some(function),
            _ => None,
        })
        .unwrap();
    let replay = function
        .block
        .stmts
        .iter()
        .filter_map(|statement| match statement {
            Stmt::Expr(Expr::If(branch), _)
                if branch.then_branch.stmts.iter().any(measured_binding) =>
            {
                Some(branch)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(replay.len(), 1);
    let replay = replay[0];
    let Expr::Let(condition) = &*replay.cond else {
        panic!("explicit replay condition")
    };
    assert_eq!(condition.pat, syn::parse_quote!(Some(replay)));
    assert_eq!(condition.expr, syn::parse_quote!(&replay));
    let branch = calls(&replay.then_branch);
    assert_eq!(
        branch
            .iter()
            .filter(|call| target(call, "measured"))
            .count(),
        1
    );
    assert!(!branch.iter().any(|call| target(call, "OpenEventW")));
    let marker_calls = branch
        .iter()
        .filter(|call| target(call, "replay_marker"))
        .collect::<Vec<_>>();
    assert_eq!(marker_calls.len(), 2);
    assert_eq!(
        calls(&function.block)
            .iter()
            .filter(|call| target(call, "replay_marker"))
            .count(),
        2
    );
    for phase in ["pre", "post"] {
        let packet = branch.iter().filter(|call| matches!(&*call.func, Expr::Path(path) if path.path.segments.iter().map(|segment| segment.ident.to_string()).collect::<Vec<_>>() == ["call_packet", "Packet", phase])).collect::<Vec<_>>();
        assert_eq!(packet.len(), 1);
        assert_eq!(
            packet[0].args[1],
            syn::parse_quote!(measured as usize as u64)
        );
    }
    let measured = branch.iter().find(|call| target(call, "measured")).unwrap();
    assert_eq!(
        measured.args,
        syn::parse_quote!(SYNCHRONIZATION_SYNCHRONIZE, 0, name.as_ptr())
    );
    let original = calls(&function.block)
        .into_iter()
        .filter(|call| {
            target(call, "OpenEventW")
                && call.args.first().is_some_and(|argument| {
                    *argument == syn::parse_quote!(SYNCHRONIZATION_SYNCHRONIZE)
                })
        })
        .collect::<Vec<_>>();
    assert_eq!(original.len(), 1);
    assert_eq!(original[0].args, measured.args);
}
