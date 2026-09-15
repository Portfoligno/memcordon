//! Syntax-only boundary evidence. These measurements never authorize a split.
//!
//! Imports and calls are lexical approximations, not compiler name resolution.
//! Macro expansions and inactive cfg selection are deliberately not inferred.
use std::collections::{BTreeMap, BTreeSet};

use quote::ToTokens;
use serde::Serialize;
use syn::visit::{self, Visit};

#[derive(Debug, Default, Serialize)]
pub struct SyntaxMetrics {
    pub items: usize,
    pub public_items: usize,
    pub restricted_items: usize,
    pub private_items: usize,
    pub unsafe_blocks: usize,
    pub unsafe_functions: usize,
    pub cfg_regions: usize,
    pub imports: BTreeSet<String>,
    /// Occurrence identities, including a deterministic traversal ordinal.
    pub functions: BTreeSet<String>,
    /// Occurrence identity to lexical qualified name; cfg alternatives stay distinct.
    pub function_names: BTreeMap<String, String>,
    pub calls: BTreeMap<String, BTreeSet<String>>,
    pub test_functions: BTreeSet<String>,
}

#[derive(Debug, Serialize)]
pub struct FileMetrics {
    pub path: String,
    pub syntax: SyntaxMetrics,
    /// Lexical import paths with a segment uniquely naming a supplied file stem.
    pub approximate_imports: BTreeSet<String>,
    pub approximate_importers: BTreeSet<String>,
    pub approximate_test_references: BTreeSet<String>,
    /// Connected components of calls to uniquely named local functions.
    pub approximate_call_clusters: Vec<BTreeSet<String>>,
    pub cochanges: BTreeMap<String, usize>,
}

struct Collector {
    metrics: SyntaxMetrics,
    scope: Vec<String>,
    caller: Option<String>,
}

impl Collector {
    fn visibility(&mut self, visibility: &syn::Visibility) {
        self.metrics.items += 1;
        match visibility {
            syn::Visibility::Public(_) => self.metrics.public_items += 1,
            syn::Visibility::Restricted(_) => self.metrics.restricted_items += 1,
            syn::Visibility::Inherited => self.metrics.private_items += 1,
        }
    }

    fn function(
        &mut self,
        signature: &syn::Signature,
        attributes: &[syn::Attribute],
    ) -> Option<String> {
        let mut parts = self.scope.clone();
        parts.push(signature.ident.to_string());
        let name = parts.join("::");
        let ordinal = self.metrics.functions.len();
        let identity = format!("{name}#{ordinal}");
        self.metrics.functions.insert(identity.clone());
        self.metrics.function_names.insert(identity.clone(), name);
        self.metrics.calls.entry(identity.clone()).or_default();
        if attributes
            .iter()
            .any(|attribute| attribute.path().is_ident("test"))
        {
            self.metrics.test_functions.insert(identity.clone());
        }
        self.caller.replace(identity)
    }
}

impl<'ast> Visit<'ast> for Collector {
    fn visit_signature(&mut self, signature: &'ast syn::Signature) {
        self.metrics.unsafe_functions +=
            usize::from(matches!(signature.safety, syn::Safety::Unsafe(_)));
        visit::visit_signature(self, signature);
    }
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let visibility = match item {
            syn::Item::Const(v) => Some(&v.vis),
            syn::Item::Enum(v) => Some(&v.vis),
            syn::Item::ExternCrate(v) => Some(&v.vis),
            syn::Item::Fn(v) => Some(&v.vis),
            syn::Item::Mod(v) => Some(&v.vis),
            syn::Item::Static(v) => Some(&v.vis),
            syn::Item::Struct(v) => Some(&v.vis),
            syn::Item::Trait(v) => Some(&v.vis),
            syn::Item::TraitAlias(v) => Some(&v.vis),
            syn::Item::Type(v) => Some(&v.vis),
            syn::Item::Union(v) => Some(&v.vis),
            syn::Item::Use(v) => Some(&v.vis),
            _ => None,
        };
        self.visibility(visibility.unwrap_or(&syn::Visibility::Inherited));
        visit::visit_item(self, item);
    }
    fn visit_item_mod(&mut self, item: &'ast syn::ItemMod) {
        self.scope.push(item.ident.to_string());
        visit::visit_item_mod(self, item);
        self.scope.pop();
    }
    fn visit_item_impl(&mut self, item: &'ast syn::ItemImpl) {
        let ordinal = self.metrics.items;
        self.scope.push(format!(
            "impl[{ordinal}]:{}",
            item.self_ty.to_token_stream()
        ));
        visit::visit_item_impl(self, item);
        self.scope.pop();
    }
    fn visit_item_fn(&mut self, item: &'ast syn::ItemFn) {
        let previous = self.function(&item.sig, &item.attrs);
        self.scope.push(item.sig.ident.to_string());
        visit::visit_item_fn(self, item);
        self.scope.pop();
        self.caller = previous;
    }
    fn visit_impl_item_fn(&mut self, item: &'ast syn::ImplItemFn) {
        self.visibility(&item.vis);
        let previous = self.function(&item.sig, &item.attrs);
        self.scope.push(item.sig.ident.to_string());
        visit::visit_impl_item_fn(self, item);
        self.scope.pop();
        self.caller = previous;
    }
    fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
        self.metrics.cfg_regions +=
            usize::from(attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr"));
        visit::visit_attribute(self, attribute);
    }
    fn visit_expr_unsafe(&mut self, expression: &'ast syn::ExprUnsafe) {
        self.metrics.unsafe_blocks += 1;
        visit::visit_expr_unsafe(self, expression);
    }
    fn visit_item_use(&mut self, item: &'ast syn::ItemUse) {
        fn flatten(tree: &syn::UseTree, prefix: Vec<String>, output: &mut BTreeSet<String>) {
            match tree {
                syn::UseTree::Path(path) => {
                    let mut next = prefix;
                    next.push(path.ident.to_string());
                    flatten(&path.tree, next, output);
                }
                syn::UseTree::Group(group) => {
                    for item in &group.items {
                        flatten(item, prefix.clone(), output);
                    }
                }
                syn::UseTree::Name(name) => {
                    let mut parts = prefix;
                    parts.push(name.ident.to_string());
                    output.insert(parts.join("::"));
                }
                syn::UseTree::Rename(rename) => {
                    let mut parts = prefix;
                    parts.push(rename.ident.to_string());
                    output.insert(parts.join("::"));
                }
                syn::UseTree::Glob(_) => {
                    let mut parts = prefix;
                    parts.push("*".into());
                    output.insert(parts.join("::"));
                }
            }
        }
        flatten(&item.tree, Vec::new(), &mut self.metrics.imports);
        visit::visit_item_use(self, item);
    }
    fn visit_expr_call(&mut self, expression: &'ast syn::ExprCall) {
        if let (Some(caller), syn::Expr::Path(path)) = (&self.caller, expression.func.as_ref()) {
            self.metrics
                .calls
                .entry(caller.clone())
                .or_default()
                .insert(path.path.to_token_stream().to_string().replace(' ', ""));
        }
        visit::visit_expr_call(self, expression);
    }
}

pub fn analyze_source(source: &str) -> Result<SyntaxMetrics, syn::Error> {
    let syntax = syn::parse_file(source)?;
    let mut collector = Collector {
        metrics: SyntaxMetrics::default(),
        scope: Vec::new(),
        caller: None,
    };
    collector.visit_file(&syntax);
    Ok(collector.metrics)
}

/// Each history element is one commit's distinct changed paths. The caller owns
/// the history range, commit identity, tracked inventory, and output provenance.
pub fn analyze_files(
    sources: &BTreeMap<String, String>,
    history: &[BTreeSet<String>],
) -> Result<Vec<FileMetrics>, syn::Error> {
    let mut files = Vec::new();
    let mut stems: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for path in sources.keys() {
        if let Some(stem) = std::path::Path::new(path)
            .file_stem()
            .and_then(|s| s.to_str())
        {
            stems.entry(stem.into()).or_default().push(path.clone());
        }
    }
    for (path, source) in sources {
        let syntax = analyze_source(source)?;
        let mut imports = BTreeSet::new();
        for import in &syntax.imports {
            for segment in import.split("::") {
                if let Some(matches) = stems.get(segment)
                    && matches.len() == 1
                    && matches[0] != *path
                {
                    imports.insert(matches[0].clone());
                }
            }
        }
        let mut edges: BTreeMap<String, BTreeSet<String>> = syntax
            .functions
            .iter()
            .map(|name| (name.clone(), BTreeSet::new()))
            .collect();
        for (caller, calls) in &syntax.calls {
            for call in calls {
                let matches: Vec<_> = syntax
                    .function_names
                    .iter()
                    .filter(|(_, name)| {
                        *name == call || name.rsplit("::").next() == Some(call.as_str())
                    })
                    .map(|(identity, _)| identity)
                    .collect();
                if let [callee] = matches.as_slice() {
                    edges
                        .entry(caller.clone())
                        .or_default()
                        .insert((*callee).clone());
                    edges
                        .entry((*callee).clone())
                        .or_default()
                        .insert(caller.clone());
                }
            }
        }
        let mut clusters = Vec::new();
        while let Some(start) = edges.keys().next().cloned() {
            let mut cluster = BTreeSet::new();
            let mut pending = vec![start];
            while let Some(node) = pending.pop() {
                if cluster.insert(node.clone()) {
                    pending.extend(edges.remove(&node).unwrap_or_default());
                }
            }
            clusters.push(cluster);
        }
        let mut cochanges = BTreeMap::new();
        for commit in history.iter().filter(|commit| commit.contains(path)) {
            for other in commit
                .iter()
                .filter(|other| *other != path && sources.contains_key(*other))
            {
                *cochanges.entry(other.clone()).or_default() += 1;
            }
        }
        files.push(FileMetrics {
            path: path.clone(),
            syntax,
            approximate_imports: imports,
            approximate_importers: BTreeSet::new(),
            approximate_test_references: BTreeSet::new(),
            approximate_call_clusters: clusters,
            cochanges,
        });
    }
    let links: Vec<_> = files
        .iter()
        .flat_map(|file| {
            file.approximate_imports.iter().map(|target| {
                (
                    file.path.clone(),
                    target.clone(),
                    file.path.split('/').any(|part| part == "tests")
                        || !file.syntax.test_functions.is_empty(),
                )
            })
        })
        .collect();
    for file in &mut files {
        for (source, target, test) in &links {
            if target == &file.path {
                file.approximate_importers.insert(source.clone());
                if *test {
                    file.approximate_test_references.insert(source.clone());
                }
            }
        }
    }
    Ok(files)
}
