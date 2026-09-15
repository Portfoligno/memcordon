//! Owner: source governance. Syntax edges describe all cfgs, not host-only reachability.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

use super::{inventory, schema::Source};
use crate::{CiError, Result};
use quote::ToTokens;
use syn::visit::Visit;
use syn::{Expr, Item, Lit, Meta};

fn cfg_attributes(attributes: &[syn::Attribute]) -> Vec<String> {
    attributes
        .iter()
        .filter_map(|attribute| {
            let Meta::List(list) = &attribute.meta else {
                return None;
            };
            (list.path.is_ident("cfg") || list.path.is_ident("cfg_attr")).then(|| {
                format!(
                    "{}({})",
                    list.path.segments.last().expect("cfg has a name").ident,
                    list.tokens
                )
            })
        })
        .collect()
}

fn visibility(value: &syn::Visibility) -> String {
    match value {
        syn::Visibility::Inherited => "private".into(),
        syn::Visibility::Public(_) => "pub".into(),
        syn::Visibility::Restricted(value) => {
            let path = value
                .path
                .segments
                .iter()
                .map(|segment| segment.ident.to_string())
                .collect::<Vec<_>>()
                .join("::");
            format!("pub({path})")
        }
    }
}

#[derive(Default)]
struct Surface {
    cfg: Vec<String>,
    items: Vec<String>,
    owner: Vec<String>,
    expression_index: usize,
    occurrences: BTreeMap<String, usize>,
}

impl Surface {
    fn enter(&mut self, name: String, vis: Option<&syn::Visibility>) {
        let mut key = self.owner.clone();
        key.push(name.clone());
        let count = self.occurrences.entry(key.join("/")).or_default();
        *count += 1;
        self.owner.push(format!("{name}#{count}"));
        if let Some(vis) = vis {
            self.items
                .push(format!("{}:{}", self.owner.join("/"), visibility(vis)));
        }
    }
}

impl<'ast> Visit<'ast> for Surface {
    fn visit_attribute(&mut self, attribute: &'ast syn::Attribute) {
        for cfg in cfg_attributes(std::slice::from_ref(attribute)) {
            self.cfg.push(format!("{}:{cfg}", self.owner.join("/")));
        }
        syn::visit::visit_attribute(self, attribute);
    }

    fn visit_item(&mut self, item: &'ast Item) {
        let (name, vis) = match item {
            Item::Const(item) => (format!("const:{}", item.ident), Some(&item.vis)),
            Item::Enum(item) => (format!("enum:{}", item.ident), Some(&item.vis)),
            Item::Fn(item) => (format!("fn:{}", item.sig.ident), Some(&item.vis)),
            Item::Mod(item) => (format!("mod:{}", item.ident), Some(&item.vis)),
            Item::Static(item) => (format!("static:{}", item.ident), Some(&item.vis)),
            Item::Struct(item) => (format!("struct:{}", item.ident), Some(&item.vis)),
            Item::Trait(item) => (format!("trait:{}", item.ident), Some(&item.vis)),
            Item::Type(item) => (format!("type:{}", item.ident), Some(&item.vis)),
            Item::Union(item) => (format!("union:{}", item.ident), Some(&item.vis)),
            Item::Use(item) => (
                format!("use:{}", item.tree.to_token_stream()),
                Some(&item.vis),
            ),
            Item::ExternCrate(item) => (
                format!("extern:{}", item.to_token_stream()),
                Some(&item.vis),
            ),
            Item::Impl(item) => (
                format!(
                    "impl:{}:{}",
                    item.self_ty.to_token_stream(),
                    item.trait_
                        .as_ref()
                        .map(|(path, _)| path.to_token_stream().to_string())
                        .unwrap_or_default()
                ),
                None,
            ),
            Item::ForeignMod(item) => (format!("foreign:{}", item.abi.to_token_stream()), None),
            Item::Macro(item) => (format!("macro:{}", item.mac.path.to_token_stream()), None),
            _ => ("other-item".into(), None),
        };
        self.enter(name, vis);
        syn::visit::visit_item(self, item);
        self.owner.pop();
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let (name, vis) = match item {
            syn::ImplItem::Fn(item) => (format!("method:{}", item.sig.ident), Some(&item.vis)),
            syn::ImplItem::Const(item) => (format!("const:{}", item.ident), Some(&item.vis)),
            syn::ImplItem::Type(item) => (format!("type:{}", item.ident), Some(&item.vis)),
            _ => (format!("impl-item:{}", item.to_token_stream()), None),
        };
        self.enter(name, vis);
        syn::visit::visit_impl_item(self, item);
        self.owner.pop();
    }

    fn visit_field(&mut self, field: &'ast syn::Field) {
        let name = field
            .ident
            .as_ref()
            .map(ToString::to_string)
            .unwrap_or_else(|| field.ty.to_token_stream().to_string());
        self.enter(format!("field:{name}"), Some(&field.vis));
        syn::visit::visit_field(self, field);
        self.owner.pop();
    }

    fn visit_variant(&mut self, variant: &'ast syn::Variant) {
        self.enter(format!("variant:{}", variant.ident), None);
        self.items
            .push(format!("{}:enum-member", self.owner.join("/")));
        syn::visit::visit_variant(self, variant);
        self.owner.pop();
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        let name = match item {
            syn::TraitItem::Fn(item) => format!("method:{}", item.sig.ident),
            syn::TraitItem::Const(item) => format!("const:{}", item.ident),
            syn::TraitItem::Type(item) => format!("type:{}", item.ident),
            _ => format!("trait-item:{}", item.to_token_stream()),
        };
        self.enter(name, None);
        self.items
            .push(format!("{}:trait-member", self.owner.join("/")));
        syn::visit::visit_trait_item(self, item);
        self.owner.pop();
    }

    fn visit_fields_unnamed(&mut self, fields: &'ast syn::FieldsUnnamed) {
        for (index, field) in fields.unnamed.iter().enumerate() {
            self.enter(format!("tuple:{index}"), None);
            self.visit_field(field);
            self.owner.pop();
        }
    }

    fn visit_expr(&mut self, expression: &'ast syn::Expr) {
        self.expression_index += 1;
        self.enter(format!("expression:{}", self.expression_index), None);
        syn::visit::visit_expr(self, expression);
        self.owner.pop();
    }

    fn visit_local(&mut self, local: &'ast syn::Local) {
        self.expression_index += 1;
        self.enter(format!("local:{}", self.expression_index), None);
        syn::visit::visit_local(self, local);
        self.owner.pop();
    }

    fn visit_foreign_item(&mut self, item: &'ast syn::ForeignItem) {
        let (name, vis) = match item {
            syn::ForeignItem::Fn(item) => (format!("fn:{}", item.sig.ident), Some(&item.vis)),
            syn::ForeignItem::Static(item) => (format!("static:{}", item.ident), Some(&item.vis)),
            syn::ForeignItem::Type(item) => (format!("type:{}", item.ident), Some(&item.vis)),
            _ => (format!("foreign-item:{}", item.to_token_stream()), None),
        };
        self.enter(name, vis);
        syn::visit::visit_foreign_item(self, item);
        self.owner.pop();
    }
}

/// Reviewable syntax facts. All cfg branches are retained, including cfg_attr.
pub(super) fn surface(bytes: &str) -> Result<(Vec<String>, Vec<String>)> {
    let syntax = syn::parse_file(bytes)
        .map_err(|error| CiError::Message(format!("cannot parse source surface: {error}")))?;
    let mut surface = Surface::default();
    surface.visit_file(&syntax);
    surface.items.sort();
    surface.cfg.sort();
    Ok((surface.cfg, surface.items))
}

fn normalize(path: &Path) -> Result<PathBuf> {
    let mut result = PathBuf::new();
    for part in path.components() {
        match part {
            Component::Normal(value) => result.push(value),
            Component::CurDir => {}
            Component::ParentDir if result.pop() => {}
            _ => {
                return Err(CiError::Message(format!(
                    "module route escapes workspace: {path:?}"
                )));
            }
        }
    }
    Ok(result)
}

fn portable_path(path: &Path) -> Result<String> {
    path.components()
        .map(|component| {
            let Component::Normal(value) = component else {
                return Err(CiError::Message(
                    "source route is not workspace-relative".into(),
                ));
            };
            value
                .to_str()
                .ok_or_else(|| CiError::Message("source route is not UTF-8".into()))
        })
        .collect::<Result<Vec<_>>>()
        .map(|components| components.join("/"))
}

fn modules(
    root: &Path,
    source: &str,
    directory: &Path,
    items: &[Item],
    edges: &mut BTreeMap<String, BTreeSet<String>>,
) -> Result<()> {
    for item in items {
        let Item::Mod(module) = item else { continue };
        let name = module.ident.to_string();
        let explicit = module.attrs.iter().find_map(|attribute| {
            if !attribute.path().is_ident("path") {
                return None;
            }
            let Meta::NameValue(value) = &attribute.meta else {
                return None;
            };
            let Expr::Lit(value) = &value.value else {
                return None;
            };
            let Lit::Str(value) = &value.lit else {
                return None;
            };
            Some(value.value())
        });
        if let Some((_, items)) = &module.content {
            let child = explicit.map_or_else(|| directory.join(&name), |path| directory.join(path));
            modules(root, source, &child, items, edges)?;
        } else {
            let route_kind = if explicit.is_some() {
                "path-module"
            } else {
                "module"
            };
            let candidates = if let Some(path) = explicit {
                vec![directory.join(path)]
            } else {
                vec![
                    directory.join(&name).with_extension("rs"),
                    directory.join(&name).join("mod.rs"),
                ]
            };
            for path in candidates {
                let path = normalize(&path)?;
                if root.join(&path).is_file() {
                    let path = portable_path(&path)?;
                    edges.entry(path.to_owned()).or_default().insert(format!(
                        "{route_kind}:{source}:{name}:{}:{:?}",
                        visibility(&module.vis),
                        cfg_attributes(&module.attrs)
                    ));
                }
            }
        }
    }
    Ok(())
}

pub(super) fn discover(root: &Path) -> Result<BTreeMap<String, BTreeSet<String>>> {
    let paths = inventory::sources(root)?;
    let mut edges = BTreeMap::<String, BTreeSet<String>>::new();
    for entry in fs::read_dir(root.join(".github/workflows"))? {
        let entry = entry?;
        if !entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "yml" || extension == "yaml")
        {
            continue;
        }
        let bytes = fs::read(entry.path())?;
        if bytes.len() > crate::policy::MAXIMUM_YAML_BYTES {
            return Err(CiError::Message(
                "source route workflow exceeds size bound".into(),
            ));
        }
        let workflow: serde_yaml::Value = serde_yaml::from_slice(&bytes)?;
        for (job, definition) in workflow
            .get("jobs")
            .and_then(serde_yaml::Value::as_mapping)
            .into_iter()
            .flatten()
        {
            for step in definition
                .get("steps")
                .and_then(serde_yaml::Value::as_sequence)
                .into_iter()
                .flatten()
            {
                if let Some(run) = step.get("run").and_then(serde_yaml::Value::as_str) {
                    let arguments: Vec<_> = run.split_ascii_whitespace().collect();
                    if arguments.contains(&"rustc") {
                        for argument in &arguments {
                            if paths.contains(*argument) {
                                edges
                                    .entry((*argument).to_owned())
                                    .or_default()
                                    .insert(format!(
                                        "rustc:workflow:{}:{}",
                                        entry.file_name().to_string_lossy(),
                                        job.as_str().ok_or_else(|| CiError::Message(
                                            "workflow job name is not text".into()
                                        ))?
                                    ));
                            }
                        }
                    }
                }
            }
        }
    }
    // Cargo metadata supplies target roots and exact package/target names.
    let metadata = crate::policy::workspace_metadata(root)?;
    let mut roots = BTreeSet::new();
    for package in &metadata.packages {
        if !metadata.workspace_members.contains(&package.id) {
            continue;
        }
        for target in &package.targets {
            let path = target
                .src_path
                .as_std_path()
                .strip_prefix(root)
                .map_err(|_| CiError::Message("Cargo target escapes workspace".into()))?;
            let path = portable_path(path)?;
            roots.insert(path.to_owned());
            for kind in &target.kind {
                edges.entry(path.to_owned()).or_default().insert(format!(
                    "cargo:{}:{kind}:{}:features={:?}",
                    package.name, target.name, target.required_features
                ));
            }
        }
    }
    // The independent fuzz workspace has explicit bin roots and is not returned
    // by the production workspace metadata call.
    let fuzz: toml::Value = toml::from_str(&fs::read_to_string(root.join("fuzz/Cargo.toml"))?)?;
    for bin in fuzz
        .get("bin")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
    {
        let name = bin
            .get("name")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| CiError::Message("fuzz target is unnamed".into()))?;
        let path = bin
            .get("path")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| CiError::Message("fuzz target needs an explicit path".into()))?;
        let path = normalize(&Path::new("fuzz").join(path))?;
        let path = portable_path(&path)?;
        roots.insert(path.to_owned());
        edges
            .entry(path.to_owned())
            .or_default()
            .insert(format!("cargo:memcordon-fuzz:bin:{name}"));
    }
    // Resolve explicit paths first: a path-included file's ordinary children
    // are relative to that file's parent, not a directory named for its stem.
    for path in &paths {
        let parent = Path::new(path).parent().expect("source has a parent");
        let syntax = syn::parse_file(&fs::read_to_string(root.join(path))?)
            .map_err(|error| CiError::Message(format!("cannot parse source {path}: {error}")))?;
        for item in &syntax.items {
            if matches!(item, Item::Mod(module) if module.content.is_none() && module.attrs.iter().any(|attribute| attribute.path().is_ident("path")))
            {
                modules(root, path, parent, std::slice::from_ref(item), &mut edges)?;
            }
        }
    }
    let path_included: BTreeSet<_> = edges
        .iter()
        .filter(|(_, routes)| routes.iter().any(|route| route.starts_with("path-module:")))
        .map(|(path, _)| path.clone())
        .collect();
    for path in &paths {
        let file = Path::new(path);
        let parent = file.parent().expect("source path has a parent");
        let syntax = syn::parse_file(&fs::read_to_string(root.join(file))?)
            .map_err(|error| CiError::Message(format!("cannot parse source {path}: {error}")))?;
        let module_directory = if roots.contains(path)
            || path_included.contains(path)
            || file.file_name().is_some_and(|name| name == "mod.rs")
        {
            parent.to_path_buf()
        } else {
            parent.join(file.file_stem().expect("Rust source has a stem"))
        };
        // #[path] on an out-of-line module is relative to the containing source
        // directory, whereas ordinary child modules use the module directory.
        for item in &syntax.items {
            let explicit = matches!(item, Item::Mod(module) if module.content.is_none() && module.attrs.iter().any(|attribute| attribute.path().is_ident("path")));
            modules(
                root,
                path,
                if explicit { parent } else { &module_directory },
                std::slice::from_ref(item),
                &mut edges,
            )?;
        }
    }
    Ok(edges)
}

pub(super) fn validate(root: &Path, records: &[Source]) -> Result<()> {
    let discovered = discover(root)?;
    for source in records {
        let (cfg, item_visibility) = surface(&fs::read_to_string(root.join(&source.path))?)?;
        if cfg != source.cfg || item_visibility != source.item_visibility {
            return Err(CiError::Message(format!(
                "source cfg or item visibility changed without review: {}",
                source.path
            )));
        }
        let declared: BTreeSet<_> = source.routes.iter().cloned().collect();
        let actual = discovered.get(&source.path).cloned().unwrap_or_default();
        if declared != actual {
            return Err(CiError::Message(format!(
                "source routes differ for {}: declared={declared:?}, actual={actual:?}",
                source.path
            )));
        }
    }
    Ok(())
}
