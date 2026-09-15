//! Owner: API governance. Authority: declaration drift checks, not native admission.
//! Inputs: Cargo library roots, checked-in tiers and Rust syntax across every cfg branch.
//! Output: exact root-export agreement; this is not a complete semantic-version checker.
//! Invariant: aliases, conditional visibility and glob source changes require review.
//! Primary tests: tests/api_surface.rs and downstream stable_api integration crates.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path};

use quote::ToTokens;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use syn::parse::Parser;
use syn::{Attribute, Item, UseTree, Visibility};

use crate::{CiError, Result};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Tier {
    StablePublic,
    VersionedProviderContract,
    HiddenNativeHook,
    ToolingOnly,
    TestOnly,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(deny_unknown_fields)]
pub struct ExportFact {
    pub name: String,
    pub origin: String,
    pub kind: String,
    pub cfg: Vec<String>,
    pub hidden: bool,
    pub glob_source_sha256: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Export {
    pub fact: ExportFact,
    pub tier: Tier,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Surface {
    pub package: String,
    pub root: String,
    pub fixtures: Vec<String>,
    pub exports: Vec<Export>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub schema: u32,
    pub surface: Vec<Surface>,
}

fn error(detail: impl Into<String>) -> CiError {
    CiError::Message(detail.into())
}

fn attributes(attributes: &[Attribute]) -> (Vec<String>, bool) {
    let mut cfg = Vec::new();
    let mut hidden = false;
    for attribute in attributes {
        if attribute.path().is_ident("cfg") || attribute.path().is_ident("cfg_attr") {
            cfg.push(attribute.meta.to_token_stream().to_string());
        }
        if attribute.path().is_ident("doc") {
            let _ = attribute.parse_nested_meta(|meta| {
                hidden |= meta.path.is_ident("hidden");
                Ok(())
            });
        }
    }
    cfg.sort();
    (cfg, hidden)
}

fn imports(tree: &UseTree, prefix: &[String], output: &mut Vec<(String, String)>) {
    match tree {
        UseTree::Path(path) => {
            let mut prefix = prefix.to_vec();
            prefix.push(path.ident.to_string());
            imports(&path.tree, &prefix, output);
        }
        UseTree::Group(group) => {
            for tree in &group.items {
                imports(tree, prefix, output);
            }
        }
        UseTree::Name(name) => {
            let mut path = prefix.to_vec();
            path.push(name.ident.to_string());
            let exported = if name.ident == "self" {
                prefix.last().cloned().unwrap_or_else(|| "self".into())
            } else {
                name.ident.to_string()
            };
            output.push((exported, path.join("::")));
        }
        UseTree::Rename(rename) => {
            let mut path = prefix.to_vec();
            path.push(rename.ident.to_string());
            output.push((rename.rename.to_string(), path.join("::")));
        }
        UseTree::Glob(_) => {
            let mut path = prefix.to_vec();
            path.push("*".into());
            output.push(("*".into(), path.join("::")));
        }
    }
}

/// Lexical crate-root exports, retaining every cfg alternative. Glob contents
/// are bound by inspect_root; external macro expansion is not inferred here.
pub fn inspect_source(source: &str) -> Result<Vec<ExportFact>> {
    let file = syn::parse_file(source).map_err(|cause| error(cause.to_string()))?;
    let mut facts = Vec::new();
    for item in file.items {
        if let Item::Use(item) = &item {
            if matches!(item.vis, Visibility::Public(_)) {
                let (cfg, hidden) = attributes(&item.attrs);
                let mut routes = Vec::new();
                imports(&item.tree, &[], &mut routes);
                for (name, origin) in routes {
                    facts.push(ExportFact {
                        name,
                        origin,
                        kind: "reexport".into(),
                        cfg: cfg.clone(),
                        hidden,
                        glob_source_sha256: None,
                    });
                }
            }
            continue;
        }
        let (name, kind, visibility, attrs) = match &item {
            Item::Mod(item) => (&item.ident, "module", &item.vis, &item.attrs),
            Item::Struct(item) => (&item.ident, "struct", &item.vis, &item.attrs),
            Item::Enum(item) => (&item.ident, "enum", &item.vis, &item.attrs),
            Item::Union(item) => (&item.ident, "union", &item.vis, &item.attrs),
            Item::Fn(item) => (&item.sig.ident, "function", &item.vis, &item.attrs),
            Item::Const(item) => (&item.ident, "constant", &item.vis, &item.attrs),
            Item::Static(item) => (&item.ident, "static", &item.vis, &item.attrs),
            Item::Type(item) => (&item.ident, "type", &item.vis, &item.attrs),
            Item::Trait(item) => (&item.ident, "trait", &item.vis, &item.attrs),
            _ => continue,
        };
        if matches!(visibility, Visibility::Public(_)) {
            let (cfg, hidden) = attributes(attrs);
            facts.push(ExportFact {
                name: name.to_string(),
                origin: name.to_string(),
                kind: kind.into(),
                cfg,
                hidden,
                glob_source_sha256: None,
            });
        }
    }
    facts.sort();
    Ok(facts)
}

fn safe_relative(path: &str) -> Result<&Path> {
    let value = Path::new(path);
    if value.as_os_str().is_empty()
        || value
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(error(
            "API surface path must be a normal repository-relative path",
        ));
    }
    Ok(value)
}

pub fn inspect_root(root: &Path, relative: &str) -> Result<Vec<ExportFact>> {
    let canonical_root = root.canonicalize()?;
    let file = root.join(safe_relative(relative)?).canonicalize()?;
    if !file.starts_with(&canonical_root) {
        return Err(error("API library root escapes checkout"));
    }
    let source = std::fs::read_to_string(&file)?;
    let parsed = syn::parse_file(&source).map_err(|cause| error(cause.to_string()))?;
    let mut facts = inspect_source(&source)?;
    for fact in &mut facts {
        if fact.name == "*" {
            let mut path = fact.origin.split("::");
            let module = path.next().ok_or_else(|| error("glob module is absent"))?;
            if path.next() != Some("*") || path.next().is_some() {
                return Err(error(
                    "root glob must name one local module with reviewable source",
                ));
            }
            let declarations = parsed
                .items
                .iter()
                .filter_map(|item| match item {
                    Item::Mod(item) if item.ident == module => Some(item),
                    _ => None,
                })
                .collect::<Vec<_>>();
            let [declaration] = declarations.as_slice() else {
                return Err(error(
                    "root glob requires exactly one local module declaration",
                ));
            };
            if declaration.content.is_some()
                || declaration.attrs.iter().any(|attr| {
                    attr.path().is_ident("path")
                        || attr.path().is_ident("cfg")
                        || attr.path().is_ident("cfg_attr")
                })
            {
                return Err(error(
                    "root glob cannot use inline, redirected or conditional module declarations",
                ));
            }
            let target = file
                .parent()
                .ok_or_else(|| error("API root parent absent"))?
                .join(module)
                .with_extension("rs")
                .canonicalize()?;
            if !target.starts_with(&canonical_root) {
                return Err(error("API glob source escapes checkout"));
            }
            let bytes = std::fs::read(target)?;
            fact.glob_source_sha256 = Some(hex::encode(Sha256::digest(bytes)));
        }
    }
    Ok(facts)
}

pub fn validate_surface(surface: &Surface, observed: &[ExportFact], published: bool) -> Result<()> {
    if surface.exports.is_empty() {
        return Err(error("API surface cannot be empty"));
    }
    let mut declared = surface
        .exports
        .iter()
        .map(|export| export.fact.clone())
        .collect::<Vec<_>>();
    declared.sort();
    if declared.windows(2).any(|pair| pair[0] == pair[1]) || declared != observed {
        return Err(error(format!(
            "crate-root API exports changed: {}",
            surface.package
        )));
    }
    for export in &surface.exports {
        if export.tier == Tier::ToolingOnly && published {
            return Err(error(
                "published library cannot declare tooling-only exports",
            ));
        }
        if export.tier == Tier::StablePublic && export.fact.hidden {
            return Err(error("doc-hidden export cannot claim stable-public tier"));
        }
        if export.tier == Tier::HiddenNativeHook && !export.fact.hidden {
            return Err(error(
                "hidden-native-hook export requires an unconditional doc(hidden) annotation",
            ));
        }
        if export.tier == Tier::TestOnly
            && published
            && !export.fact.cfg.iter().any(|cfg| requires_test_support(cfg))
        {
            return Err(error(
                "published test-only export lacks a test-support condition",
            ));
        }
    }
    if surface
        .exports
        .iter()
        .any(|export| export.tier == Tier::StablePublic)
        && surface.fixtures.is_empty()
    {
        return Err(error(
            "stable-public surface requires a downstream fixture crate",
        ));
    }
    Ok(())
}

fn requires_test_support(text: &str) -> bool {
    fn without_feature(meta: &syn::Meta) -> Option<bool> {
        match meta {
            syn::Meta::NameValue(value) if value.path.is_ident("feature") => match &value.value {
                syn::Expr::Lit(value) if matches!(&value.lit, syn::Lit::Str(name) if name.value() == "test-support") => {
                    Some(false)
                }
                _ => None,
            },
            syn::Meta::List(list) => {
                let parser =
                    syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated;
                let parts = parser.parse2(list.tokens.clone()).ok()?;
                let values = parts.iter().map(without_feature).collect::<Vec<_>>();
                if list.path.is_ident("all") || list.path.is_ident("cfg") {
                    if values.contains(&Some(false)) {
                        Some(false)
                    } else if values.iter().all(|value| *value == Some(true)) {
                        Some(true)
                    } else {
                        None
                    }
                } else if list.path.is_ident("any") {
                    if values.contains(&Some(true)) {
                        Some(true)
                    } else if values.iter().all(|value| *value == Some(false)) {
                        Some(false)
                    } else {
                        None
                    }
                } else if list.path.is_ident("not") && values.len() == 1 {
                    values[0].map(|value| !value)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
    syn::parse_str::<syn::Meta>(text)
        .ok()
        .is_some_and(|meta| meta.path().is_ident("cfg") && without_feature(&meta) == Some(false))
}

pub fn validate(root: &Path, metadata: &cargo_metadata::Metadata) -> Result<()> {
    let catalog: Catalog =
        toml::from_str(&std::fs::read_to_string(root.join("ci/api-surface.toml"))?)?;
    if catalog.schema != 1 {
        return Err(error("unsupported API surface schema"));
    }
    let canonical_root = root.canonicalize()?;
    let members = metadata.workspace_members.iter().collect::<BTreeSet<_>>();
    let mut libraries = BTreeMap::new();
    for package in &metadata.packages {
        if !members.contains(&package.id) {
            continue;
        }
        for target in &package.targets {
            if target.kind.iter().any(|kind| kind.to_string() == "lib") {
                let file = target.src_path.as_std_path().canonicalize()?;
                let relative = file
                    .strip_prefix(&canonical_root)
                    .map_err(|_| error("Cargo library escapes checkout"))?;
                libraries.insert(
                    package.name.to_string(),
                    (relative.to_string_lossy().replace('\\', "/"), package),
                );
            }
        }
    }
    let mut seen = BTreeSet::new();
    for surface in &catalog.surface {
        if !seen.insert(surface.package.clone()) {
            return Err(error("duplicate API library declaration"));
        }
        let (path, package) = libraries
            .get(&surface.package)
            .ok_or_else(|| error("API declaration has no workspace library"))?;
        if &surface.root != path {
            return Err(error("API declaration differs from Cargo library root"));
        }
        validate_surface(
            surface,
            &inspect_root(root, path)?,
            package
                .publish
                .as_ref()
                .is_none_or(|registries| !registries.is_empty()),
        )?;
        for fixture in &surface.fixtures {
            let actual = root.join(safe_relative(fixture)?).canonicalize()?;
            if !actual.starts_with(&canonical_root)
                || !package.targets.iter().any(|target| {
                    target.kind.iter().any(|kind| kind.to_string() == "test")
                        && target.src_path.as_std_path().canonicalize().ok().as_ref()
                            == Some(&actual)
                })
            {
                return Err(error(
                    "API fixture is not an independent Cargo integration-test crate",
                ));
            }
        }
    }
    if seen != libraries.into_keys().collect() {
        return Err(error("API catalog omits a workspace library"));
    }
    Ok(())
}
