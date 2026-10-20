//! Same-program bootstrap images are optional cache data, never test results.
use crate::{CiError, Result, cache::OptionalCache, command::CommandSpec, release::artifacts};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Component, Path, PathBuf},
    time::{Duration, Instant},
};

const ABI: u32 = 1;
const FORMAT: u32 = 1;
const METADATA_LIMIT: u64 = 1024 * 1024;
const IMAGE_LIMIT: u64 = 256 * 1024 * 1024;
const TOTAL_LIMIT: u64 = 512 * 1024 * 1024;
const MANIFEST: &str = "image.json";
const CANDIDATE: &str = "target/ci-bootstrap-in";
const BOOTSTRAP: &str = "target/ci-runtime/bootstrap";
const CURRENT: &str = "target/ci-runtime/current";
const IMAGE_IN: &str = "target/ci-transfer/in/driver-image";
const IMAGE_OUT: &str = "target/ci-transfer/out/driver-image";
const BOOTSTRAP_OUT: &str = "target/ci-transfer/out/driver-bootstrap";

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Recipe {
    abi: u32,
    image_format: u32,
    package: String,
    binary: String,
    profile: String,
    toolchain: String,
    features: Vec<String>,
    companions: Vec<String>,
    hosts: Vec<String>,
    enabled_hosts: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum ImageClass {
    Bootstrap,
    Current,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Member {
    name: String,
    size: u64,
    hash: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Image {
    format: u32,
    abi: u32,
    class: ImageClass,
    host: String,
    recipe: String,
    source: String,
    members: Vec<Member>,
}

struct Identity {
    key: String,
    recipe: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Protocol {
    abi: u32,
    image_format: u32,
    host: String,
}

/// A narrow startup interface, not authentication or a current compilation fact.
pub fn image_probe(_root: &Path) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string(&Protocol {
            abi: ABI,
            image_format: FORMAT,
            host: host_name().into()
        })?
    );
    Ok(())
}

fn validate_protocol(bytes: &[u8]) -> Result<()> {
    let protocol: Protocol = serde_json::from_slice(bytes)?;
    if protocol.abi != ABI || protocol.image_format != FORMAT || protocol.host != host_name() {
        return Err(error(
            "driver image native bootstrap protocol is incompatible",
        ));
    }
    Ok(())
}

fn error(message: &str) -> CiError {
    CiError::Message(message.into())
}
fn safety(message: &str) -> CiError {
    CiError::CacheSafety(Box::new(error(message)))
}

fn secondary(result: &mut Result<()>, error: CiError) {
    *result = match std::mem::replace(result, Ok(())) {
        Ok(()) => Err(error),
        Err(primary) => Err(CiError::LaneFailures {
            primary: Box::new(primary),
            secondary: Box::new(error),
        }),
    };
}

fn optional_failure(result: &mut Result<()>, error: CiError) {
    if crate::segment_cache::cache_safety_error(&error)
        || crate::work_outcome::has_unresolved_owner(&error)
    {
        secondary(result, error);
    } else {
        eprintln!("optional driver transfer unavailable: {error}");
    }
}

fn budget_check() -> Result<()> {
    if crate::preparation::active_group().is_some_and(|group| Instant::now() >= group.deadline()) {
        return Err(error("driver image operation deadline exhausted"));
    }
    Ok(())
}

fn bounded<T>(seconds: u64, operation: impl FnOnce() -> Result<T>) -> Result<T> {
    crate::preparation::with_operation(
        crate::failure_mode::FailureMode::CollectAll,
        Instant::now() + Duration::from_secs(seconds),
        operation,
    )
}

fn optional<T>(
    budget: &mut crate::segment_cache::OptionalBudget,
    operation: impl FnOnce() -> Result<T>,
) -> Result<Option<T>> {
    match budget.run(operation) {
        Ok(value) => Ok(Some(value)),
        Err(error)
            if crate::segment_cache::cache_safety_error(&error)
                || crate::work_outcome::has_unresolved_owner(&error) =>
        {
            Err(error)
        }
        Err(error) => {
            eprintln!("optional driver cache operation unavailable: {error}");
            Ok(None)
        }
    }
}

fn executable() -> &'static str {
    if cfg!(windows) {
        "memcordon-ci.exe"
    } else {
        "memcordon-ci"
    }
}

fn read_recipe(root: &Path) -> Result<Recipe> {
    image_directory(root, "ci")?;
    let bytes = bounded_file(&root.join("ci/driver-bootstrap.toml"), METADATA_LIMIT)?;
    let recipe: Recipe = toml::from_str(
        std::str::from_utf8(&bytes).map_err(|_| error("driver recipe is not UTF-8"))?,
    )?;
    if recipe.abi != ABI
        || recipe.image_format != FORMAT
        || recipe.package != "memcordon-ci"
        || recipe.binary != "memcordon-ci"
        || recipe.profile != "release"
        || !recipe.features.is_empty()
        || recipe.toolchain != crate::config::toolchains(root)?.stable
        || recipe.companions.len() > 8
        || !recipe.hosts.iter().any(|host| host == host_name())
    {
        return Err(error(
            "unsupported driver bootstrap recipe; use source bootstrap",
        ));
    }
    let mut names = BTreeSet::new();
    let mut enabled = BTreeSet::new();
    for host in &recipe.enabled_hosts {
        if !recipe.hosts.contains(host) || !enabled.insert(host) {
            return Err(error("unsupported or duplicate enabled driver host"));
        }
    }
    for name in &recipe.companions {
        if !single_name(name) || name == executable() || name == MANIFEST || !names.insert(name) {
            return Err(error("invalid driver companion inventory"));
        }
    }
    Ok(recipe)
}

fn host_name() -> &'static str {
    crate::release::distribution::native_target().unwrap_or("unsupported")
}

fn recipe_hash(recipe: &Recipe) -> Result<String> {
    Ok(artifacts::checksum(&serde_json::to_vec(recipe)?))
}

fn reuse_enabled(recipe: &Recipe) -> bool {
    recipe.enabled_hosts.iter().any(|host| host == host_name())
}

fn single_name(name: &str) -> bool {
    let mut components = Path::new(name).components();
    !name.is_empty()
        && !name.contains(['/', '\\', ':'])
        && matches!(components.next(), Some(Component::Normal(_)))
        && components.next().is_none()
}

fn ordinary(path: &Path) -> Result<std::fs::Metadata> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(safety("driver image traverses a symlink"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            return Err(safety("driver image traverses a reparse point"));
        }
    }
    Ok(metadata)
}

fn image_directory(root: &Path, relative: &str) -> Result<PathBuf> {
    let root = root.canonicalize()?;
    let mut path = root.clone();
    for component in Path::new(relative).components() {
        let Component::Normal(name) = component else {
            return Err(safety("driver image root is not relative"));
        };
        path.push(name);
        match ordinary(&path) {
            Ok(metadata) if !metadata.is_dir() => {
                return Err(safety("driver image root is not a directory"));
            }
            Ok(_) => (),
            Err(CiError::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error),
        }
    }
    Ok(path)
}

fn bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    budget_check()?;
    let metadata = ordinary(path)?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(error("driver image file kind/size exceeds bounds"));
    }
    let bytes = artifacts::read_file(path)?;
    budget_check()?;
    if bytes.len() as u64 != metadata.len() || bytes.len() as u64 > limit {
        return Err(error("driver image changed while reading"));
    }
    Ok(bytes)
}

fn validate_image(
    root: &Path,
    relative: &str,
    recipe: &Recipe,
    class: ImageClass,
    source: Option<&str>,
) -> Result<Image> {
    let directory = image_directory(root, relative)?;
    let image: Image =
        serde_json::from_slice(&bounded_file(&directory.join(MANIFEST), METADATA_LIMIT)?)?;
    if image.format != FORMAT
        || image.abi != ABI
        || image.class != class
        || image.host != host_name()
        || image.recipe != recipe_hash(recipe)?
        || source.is_some_and(|key| image.source != key)
        || image.members.len() != recipe.companions.len() + 1
    {
        return Err(error(
            "driver image identity does not match current selection",
        ));
    }
    let expected: BTreeSet<&str> = std::iter::once(executable())
        .chain(recipe.companions.iter().map(String::as_str))
        .collect();
    let mut seen = BTreeSet::new();
    let mut total = 0_u64;
    for member in &image.members {
        budget_check()?;
        if !single_name(&member.name)
            || !expected.contains(member.name.as_str())
            || !seen.insert(member.name.as_str())
            || member.size == 0
            || member.size > IMAGE_LIMIT
        {
            return Err(error("invalid driver image member"));
        }
        total = total
            .checked_add(member.size)
            .ok_or_else(|| error("driver image size overflow"))?;
        if total > TOTAL_LIMIT {
            return Err(error("driver image payload exceeds bounds"));
        }
        let bytes = bounded_file(&directory.join(&member.name), IMAGE_LIMIT)?;
        if bytes.len() as u64 != member.size || artifacts::checksum(&bytes) != member.hash {
            return Err(error("driver image member hash/size mismatch"));
        }
    }
    let actual: BTreeSet<String> = std::fs::read_dir(&directory)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<_>>()?;
    let expected: BTreeSet<String> = expected
        .into_iter()
        .chain(std::iter::once(MANIFEST))
        .map(str::to_owned)
        .collect();
    if actual != expected {
        return Err(error("driver image has undeclared members"));
    }
    Ok(image)
}

/// Validate the already adopted live image for same-run preparation transport.
/// This does not enable an executable cache host or certify required tests.
pub(crate) fn preparation_members(root: &Path) -> Result<Vec<PathBuf>> {
    let recipe = read_recipe(root)?;
    let image: Image = serde_json::from_slice(&bounded_file(
        &root.join(CURRENT).join(MANIFEST),
        METADATA_LIMIT,
    )?)?;
    // The supported cold source path deliberately adopts Bootstrap at CURRENT
    // while executable-cache rollout is disabled. Its fresh-build provenance
    // comes from the required same-run producer and preparation input record,
    // never from a fabricated Current cache identity.
    if image.class == ImageClass::Bootstrap && !image.source.is_empty() {
        return Err(error("cold preparation image has an unexpected source key"));
    }
    let selected = if image.class == ImageClass::Current {
        Some(
            identity(root, &recipe)?
                .ok_or_else(|| error("current preparation image lacks source identity"))?,
        )
    } else {
        None
    };
    let image = validate_image(
        root,
        CURRENT,
        &recipe,
        image.class,
        selected.as_ref().map(|value| value.key.as_str()),
    )?;
    Ok(image
        .members
        .into_iter()
        .map(|member| Path::new(CURRENT).join(member.name))
        .chain(std::iter::once(Path::new(CURRENT).join(MANIFEST)))
        .collect())
}

fn reset_directory(root: &Path, relative: &str) -> Result<PathBuf> {
    let path = crate::cache_restore::safe_root(root, Path::new(relative))
        .map_err(|error| CiError::CacheSafety(Box::new(error)))?;
    if path.try_exists()? {
        std::fs::remove_dir_all(&path)?;
    }
    std::fs::create_dir_all(&path)?;
    Ok(path)
}

fn copy_image(
    root: &Path,
    from: &Path,
    relative: &str,
    recipe: &Recipe,
    class: ImageClass,
    source: &str,
) -> Result<Image> {
    // The destination guard includes the currently running image on Windows
    // and Unix, and checks every existing descendant before any deletion.
    let relative_source = from
        .strip_prefix(root)
        .map_err(|_| safety("driver image source escapes checkout"))?
        .to_str()
        .ok_or_else(|| safety("driver image source is not UTF-8"))?;
    image_directory(root, relative_source)?;
    let destination = reset_directory(root, relative)?;
    let mut members = Vec::new();
    let mut total = 0_u64;
    for name in std::iter::once(executable()).chain(recipe.companions.iter().map(String::as_str)) {
        budget_check()?;
        let bytes = bounded_file(&from.join(name), IMAGE_LIMIT)?;
        if bytes.is_empty() {
            return Err(error("empty driver image member"));
        }
        total = total
            .checked_add(bytes.len() as u64)
            .ok_or_else(|| error("driver image size overflow"))?;
        if total > TOTAL_LIMIT {
            return Err(error("driver image payload exceeds bounds"));
        }
        std::fs::copy(from.join(name), destination.join(name))?;
        members.push(Member {
            name: name.into(),
            size: bytes.len() as u64,
            hash: artifacts::checksum(&bytes),
        });
    }
    let image = Image {
        format: FORMAT,
        abi: ABI,
        class,
        host: host_name().into(),
        recipe: recipe_hash(recipe)?,
        source: source.into(),
        members,
    };
    std::fs::write(destination.join(MANIFEST), serde_json::to_vec(&image)?)?;
    validate_image(root, relative, recipe, class, Some(source))
}

fn activate(
    root: &Path,
    from: &Path,
    destination: &str,
    recipe: &Recipe,
    class: ImageClass,
    source: &str,
) -> Result<()> {
    copy_image(root, from, destination, recipe, class, source)?;
    CommandSpec::new(
        root.join(destination).join(executable()),
        root,
        Duration::from_secs(30),
    )
    .args(["ci", "driver-image-probe"])
    .bootstrap_environment()
    .output_limit(64 * 1024)
    .run_owned()
    .map_validated(|bytes| validate_protocol(&bytes))
    .into_result()?;
    Ok(())
}

fn identity(root: &Path, recipe: &Recipe) -> Result<Option<Identity>> {
    let context = crate::cache::context(root, "ci-driver-build", "complete", &[])?;
    let Some(OptionalCache::Available { entry }) = context.entries.get("product") else {
        return Ok(None);
    };
    if !context.usable {
        return Ok(None);
    }
    // Metadata supplies the real resolved Cargo graph. The existing projection
    // hashes a conservative tracked resource superset with relative filenames.
    let metadata = CommandSpec::cargo("rustup", root, &recipe.toolchain, Duration::from_secs(90))
        .args(["metadata", "--locked", "--offline", "--format-version", "1"])
        .bootstrap_environment()
        .output_limit(16 * 1024 * 1024)
        .run()?;
    let metadata: cargo_metadata::Metadata = serde_json::from_slice(&metadata)?;
    let canonical_root = root.canonicalize()?;
    let driver = metadata
        .packages
        .iter()
        .find(|package| package.name.as_str() == "memcordon-ci")
        .ok_or_else(|| error("driver absent from Cargo metadata"))?;
    let resolve = metadata
        .resolve
        .as_ref()
        .ok_or_else(|| error("resolved driver graph unavailable"))?;
    let mut selected = BTreeSet::new();
    let mut remaining = vec![driver.id.clone()];
    while let Some(id) = remaining.pop() {
        if !selected.insert(id.clone()) {
            continue;
        }
        let node = resolve
            .nodes
            .iter()
            .find(|node| node.id == id)
            .ok_or_else(|| error("driver graph node unavailable"))?;
        remaining.extend(node.deps.iter().map(|dependency| dependency.pkg.clone()));
    }
    let packages: Vec<_> = metadata
        .packages
        .iter()
        .filter(|package| selected.contains(&package.id))
        .collect();
    let projected = crate::cache_inputs::local_files(root, "ci-driver-build")?;
    for package in &packages {
        if package.source.is_none()
            && !package
                .manifest_path
                .as_std_path()
                .starts_with(&canonical_root)
        {
            return Ok(None);
        }
        if package.source.is_none() {
            // Unknown local build scripts may read arbitrary VCS/time/environment
            // inputs. Disable reuse until that concrete recipe is modeled.
            if package.targets.iter().any(|target| {
                target
                    .kind
                    .iter()
                    .any(|kind| matches!(kind, cargo_metadata::TargetKind::CustomBuild))
            }) {
                return Ok(None);
            }
            let source = package
                .manifest_path
                .as_std_path()
                .parent()
                .ok_or_else(|| error("local package root unavailable"))?
                .join("src");
            for entry in walkdir::WalkDir::new(source).follow_links(false) {
                let entry = entry.map_err(|_| error("driver local input walk failed"))?;
                if entry.file_type().is_file()
                    && entry
                        .path()
                        .extension()
                        .is_some_and(|extension| extension == "rs")
                {
                    let relative = entry
                        .path()
                        .strip_prefix(&canonical_root)
                        .map_err(|_| error("driver source escapes checkout"))?
                        .to_string_lossy()
                        .replace('\\', "/");
                    if !projected.contains_key(&relative) {
                        return Ok(None);
                    }
                    if !modeled_macros(root, entry.path(), &projected)? {
                        return Ok(None);
                    }
                }
            }
        }
    }
    let mut compatibility = context.inputs;
    compatibility.insert("driver-recipe".into(), recipe_hash(recipe)?);
    compatibility.insert("driver-native-host".into(), host_name().into());
    compatibility.insert(
        "driver-cargo-graph".into(),
        artifacts::checksum(&serde_json::to_vec(&packages)?),
    );
    let content = BTreeMap::from([("workspace-build-input".into(), entry.exact_key.clone())]);
    let (key, _) = crate::cache_inputs::keys(&crate::cache_inputs::KeyInputs {
        family: "driver-image".into(),
        layout_revision: FORMAT,
        compatibility,
        content,
    })?;
    Ok(Some(Identity {
        key,
        recipe: recipe_hash(recipe)?,
    }))
}

fn modeled_macros(root: &Path, source: &Path, inputs: &BTreeMap<String, String>) -> Result<bool> {
    use syn::visit::Visit;
    struct Inputs<'a> {
        root: &'a Path,
        source: &'a Path,
        inputs: &'a BTreeMap<String, String>,
        modeled: bool,
    }
    impl<'ast> Visit<'ast> for Inputs<'_> {
        fn visit_macro(&mut self, node: &'ast syn::Macro) {
            if let Some(name) = node.path.get_ident() {
                match name.to_string().as_str() {
                    "env" | "option_env" => {
                        self.modeled &= syn::parse2::<syn::LitStr>(node.tokens.clone())
                            .is_ok_and(|name| name.value() == "CARGO_PKG_VERSION");
                    }
                    "include" | "include_str" | "include_bytes" => {
                        let selected = syn::parse2::<syn::LitStr>(node.tokens.clone())
                            .ok()
                            .and_then(|name| {
                                self.source.parent().map(|parent| parent.join(name.value()))
                            })
                            .and_then(|path| path.canonicalize().ok());
                        self.modeled &= selected
                            .and_then(|path| {
                                path.strip_prefix(self.root)
                                    .ok()
                                    .map(|path| path.to_string_lossy().replace('\\', "/"))
                            })
                            .is_some_and(|path| self.inputs.contains_key(&path));
                    }
                    _ => (),
                }
            }
            // Macro token bodies are opaque to syn's ordinary visitor. Inspect
            // expression arguments too, so format!(..., env!(...)) cannot hide
            // an embedded environment input from the identity projection.
            use syn::parse::Parser;
            if let Ok(arguments) =
                syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated
                    .parse2(node.tokens.clone())
            {
                for argument in &arguments {
                    self.visit_expr(argument);
                }
            } else {
                let text = node.tokens.to_string();
                if text.contains("env !")
                    || text.contains("option_env !")
                    || text.contains("include !")
                    || text.contains("include_str !")
                    || text.contains("include_bytes !")
                {
                    self.modeled = false;
                }
            }
            syn::visit::visit_macro(self, node);
        }
    }
    let text = bounded_file(source, 32 * 1024 * 1024)?;
    let text = std::str::from_utf8(&text).map_err(|_| error("driver Rust input is not UTF-8"))?;
    let syntax =
        syn::parse_file(text).map_err(|_| error("driver Rust input cannot be inspected"))?;
    let canonical_root = root.canonicalize()?;
    let mut visitor = Inputs {
        root: &canonical_root,
        source,
        inputs,
        modeled: true,
    };
    visitor.visit_file(&syntax);
    Ok(visitor.modeled)
}

fn modeled_depinfo(root: &Path, path: &Path) -> Result<bool> {
    let bytes = bounded_file(path, 32 * 1024 * 1024)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| error("driver dep-info is not UTF-8"))?;
    let line = text
        .lines()
        .next()
        .ok_or_else(|| error("driver dep-info is empty"))?;
    let (_, dependencies) = line
        .split_once(": ")
        .ok_or_else(|| error("driver dep-info target is absent"))?;
    let mut paths = Vec::new();
    let mut token = String::new();
    let mut chars = dependencies.chars().peekable();
    while let Some(character) = chars.next() {
        if character == '\\'
            && chars
                .peek()
                .is_some_and(|next| matches!(next, ' ' | '\\' | '#' | ':'))
        {
            token.push(chars.next().expect("peeked dep-info escape"));
        } else if character.is_whitespace() {
            if !token.is_empty() {
                paths.push(std::mem::take(&mut token));
            }
        } else {
            token.push(character);
        }
    }
    if !token.is_empty() {
        paths.push(token);
    }
    let inputs = crate::cache_inputs::local_files(root, "ci-driver-build")?;
    let root = root.canonicalize()?;
    Ok(!paths.is_empty()
        && paths.iter().all(|path| {
            Path::new(path)
                .canonicalize()
                .ok()
                .and_then(|path| {
                    path.strip_prefix(&root)
                        .ok()
                        .map(|path| path.to_string_lossy().replace('\\', "/"))
                })
                .is_some_and(|path| inputs.contains_key(&path))
        }))
}

fn optional_identity(root: &Path, recipe: &Recipe) -> Result<Option<Identity>> {
    match identity(root, recipe) {
        Err(error) if crate::segment_cache::cache_safety_error(&error) => Err(error),
        Err(error) if crate::work_outcome::has_unresolved_owner(&error) => Err(error),
        Err(error) => {
            eprintln!("optional driver identity unavailable: {error}");
            Ok(None)
        }
        result => result,
    }
}

fn trusted_write() -> bool {
    crate::segment_cache::write_event()
}

fn bootstrap_key(root: &Path, image: &Image) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut discovery = Sha256::new();
    for relative in ["ci/driver-bootstrap.toml", "ci/toolchains.toml"] {
        discovery.update(Sha256::digest(bounded_file(
            &root.join(relative),
            METADATA_LIMIT,
        )?));
    }
    let os = match std::env::consts::OS {
        "macos" => "macOS",
        "windows" => "Windows",
        "linux" => "Linux",
        _ => return Err(error("unsupported bootstrap OS")),
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => "ARM64",
        "x86_64" => "X64",
        _ => return Err(error("unsupported bootstrap architecture")),
    };
    Ok(format!(
        "mc-ci-bootstrap-v1-{os}-{arch}-{}-{}",
        hex::encode(discovery.finalize()),
        artifacts::checksum(&serde_json::to_vec(image)?)
    ))
}

fn unavailable() -> Result<()> {
    crate::workflow_output::write(&[
        ("current-ready", "false".into()),
        ("build-required", "true".into()),
        ("image-save", "false".into()),
        ("bootstrap-save", "false".into()),
        ("compiled-complete-save", "false".into()),
        ("compiled-partial-save", "false".into()),
    ])
}

/// A candidate invokes only this narrow bootstrap entrypoint, never old jobs.
pub fn bootstrap(root: &Path) -> Result<()> {
    bounded(120, || bootstrap_owned(root))
}

fn bootstrap_owned(root: &Path) -> Result<()> {
    crate::workflow_output::write(&[("bootstrap-ready", "false".into())])?;
    let recipe = read_recipe(root)?;
    if !reuse_enabled(&recipe) {
        return Ok(());
    }
    if std::env::current_exe()?.canonicalize()?
        != root.join(CANDIDATE).join(executable()).canonicalize()?
    {
        return Err(error("bootstrap must run the selected candidate image"));
    }
    validate_image(root, CANDIDATE, &recipe, ImageClass::Bootstrap, None)?;
    activate(
        root,
        &root.join(CANDIDATE),
        BOOTSTRAP,
        &recipe,
        ImageClass::Bootstrap,
        "",
    )?;
    crate::workflow_output::write(&[("bootstrap-ready", "true".into())])
}

pub fn context(root: &Path) -> Result<()> {
    bounded(240, || context_bounded(root))
}

fn context_bounded(root: &Path) -> Result<()> {
    let mut result =
        crate::segment_cache::requests(root, &[], crate::download_cache::DownloadFamily::Workspace);
    if let Err(error) = context_owned(root) {
        secondary(&mut result, error);
    }
    result
}

fn context_owned(root: &Path) -> Result<()> {
    let recipe = read_recipe(root)?;
    let selected = if reuse_enabled(&recipe) {
        optional_identity(root, &recipe)?
    } else {
        None
    };
    crate::workflow_output::write(&[
        ("image-restore", selected.is_some().to_string()),
        (
            "image-key",
            selected
                .as_ref()
                .map_or_else(String::new, |identity| format!("{}-lookup", identity.key)),
        ),
        (
            "image-prefix",
            selected
                .as_ref()
                .map_or_else(String::new, |identity| format!("{}-", identity.key)),
        ),
        ("image-inbox", IMAGE_IN.into()),
    ])?;
    let selection = compiler_selection();
    for complete in [true, false] {
        if !reuse_enabled(&recipe) {
            crate::workflow_output::write(&[(
                if complete {
                    "compiled-complete-restore"
                } else {
                    "compiled-partial-restore"
                },
                "false".into(),
            )])?;
            continue;
        }
        let prefix = if complete {
            "compiled-complete"
        } else {
            "compiled-partial"
        };
        let request = crate::cache_snapshot::transfer_request(root, selection, complete);
        match request {
            Ok(request) => crate::workflow_output::write(&[
                (
                    if complete {
                        "compiled-complete-restore"
                    } else {
                        "compiled-partial-restore"
                    },
                    "true".into(),
                ),
                (
                    if complete {
                        "compiled-complete-key"
                    } else {
                        "compiled-partial-key"
                    },
                    request.key,
                ),
                (
                    if complete {
                        "compiled-complete-prefix"
                    } else {
                        "compiled-partial-prefix"
                    },
                    request.prefix,
                ),
                (
                    if complete {
                        "compiled-complete-inbox"
                    } else {
                        "compiled-partial-inbox"
                    },
                    crate::workflow_output::action_path(&request.path)?,
                ),
            ])?,
            Err(error)
                if crate::segment_cache::cache_safety_error(&error)
                    || crate::work_outcome::has_unresolved_owner(&error) =>
            {
                return Err(error);
            }
            Err(error) => {
                eprintln!("optional {prefix} request unavailable: {error}");
                crate::workflow_output::write(&[(
                    if complete {
                        "compiled-complete-restore"
                    } else {
                        "compiled-partial-restore"
                    },
                    "false".into(),
                )])?;
            }
        }
    }
    Ok(())
}

pub fn select(root: &Path) -> Result<()> {
    bounded(240, || select_owned(root))
}

fn select_owned(root: &Path) -> Result<()> {
    unavailable()?;
    let recipe = read_recipe(root)?;
    if !reuse_enabled(&recipe) {
        return Ok(());
    }
    let Some(identity) = optional_identity(root, &recipe)? else {
        return Ok(());
    };
    if !root.join(IMAGE_IN).try_exists()? {
        return Ok(());
    }
    // Unsafe roots must remain errors; malformed ordinary cache bytes are misses.
    let directory = image_directory(root, IMAGE_IN)?;
    for entry in std::fs::read_dir(directory)? {
        ordinary(&entry?.path())?;
    }
    if let Err(error) = validate_image(
        root,
        IMAGE_IN,
        &recipe,
        ImageClass::Current,
        Some(&identity.key),
    ) {
        if crate::segment_cache::cache_safety_error(&error) {
            return Err(error);
        }
        eprintln!("driver image rejected; source build required: {error}");
        return Ok(());
    }
    let activation = activate(
        root,
        &root.join(IMAGE_IN),
        CURRENT,
        &recipe,
        ImageClass::Current,
        &identity.key,
    );
    if let Err(error) = activation {
        if crate::segment_cache::cache_safety_error(&error)
            || crate::work_outcome::has_unresolved_owner(&error)
        {
            return Err(error);
        }
        eprintln!("driver image failed native startup; source build required: {error}");
        return Ok(());
    }
    crate::workflow_output::write(&[
        ("current-ready", "true".into()),
        ("build-required", "false".into()),
        ("driver-origin", "restored-exact".into()),
    ])
}

fn compiler_selection() -> crate::cache_snapshot::TransferSelection<'static> {
    crate::cache_snapshot::TransferSelection {
        kind: crate::cache_snapshot::SnapshotKind::Compiled,
        purpose: "ci-driver-build",
        shard: "complete",
        partition: None,
    }
}

fn offer_image(
    root: &Path,
    recipe: &Recipe,
    from: &Path,
    class: ImageClass,
    source: &str,
) -> Result<()> {
    if !trusted_write() || !reuse_enabled(recipe) {
        return Ok(());
    }
    let path = if class == ImageClass::Current {
        IMAGE_OUT
    } else {
        BOOTSTRAP_OUT
    };
    let image = copy_image(root, from, path, recipe, class, source)?;
    let key = if class == ImageClass::Current {
        format!(
            "{source}-{}",
            artifacts::checksum(&serde_json::to_vec(&image)?)
        )
    } else {
        bootstrap_key(root, &image)?
    };
    crate::workflow_output::write(&[
        (
            if class == ImageClass::Current {
                "image-key"
            } else {
                "bootstrap-key"
            },
            key,
        ),
        (
            if class == ImageClass::Current {
                "image-path"
            } else {
                "bootstrap-path"
            },
            path.into(),
        ),
        (
            if class == ImageClass::Current {
                "image-save"
            } else {
                "bootstrap-save"
            },
            "true".into(),
        ),
    ])
}

/// Cold adoption does not claim a supervised complete compiler/image identity.
pub fn adopt_cold(root: &Path) -> Result<()> {
    let mut budget = crate::segment_cache::OptionalBudget::default();
    let source = budget.run(|| {
        Ok(crate::segment_cache::SourceSession::begin(
            root,
            crate::download_cache::DownloadFamily::Workspace,
        ))
    })?;
    if source.blocks_work() {
        return source.finish(
            root,
            &crate::work_outcome::WorkOutcome::observed(
                Ok(()),
                crate::work_outcome::WriterSettlement::NotStarted,
            ),
        );
    }
    let mut outcome =
        crate::work_outcome::WorkOutcome::from_result(bounded(180, || adopt_cold_owned(root)));
    if outcome.is_ok() {
        let offered = budget.run(|| {
            let recipe = read_recipe(root)?;
            offer_image(
                root,
                &recipe,
                &root.join("target/ci-driver-cold/release"),
                ImageClass::Bootstrap,
                "",
            )
        });
        if let Err(error) = offered {
            let mut result = Ok(());
            optional_failure(&mut result, error);
            outcome = outcome.post_finalization(result);
        }
    }
    // Activation only owns an image probe, not the Cargo source roots. A failed
    // loader is independent of previously established public downloads.
    finish_with_source(
        outcome,
        crate::work_outcome::WriterSettlement::NotStarted,
        |owner| optional(&mut budget, || source.finish(root, owner)).map(|_| ()),
    )
}

fn adopt_cold_owned(root: &Path) -> Result<()> {
    unavailable()?;
    let recipe = read_recipe(root)?;
    let cold = root.join("target/ci-driver-cold/release");
    if std::env::current_exe()?.canonicalize()? != cold.join(executable()).canonicalize()? {
        return Err(error("cold adoption must run the actual cold-built driver"));
    }
    let outcome = crate::work_outcome::WorkOutcome::from_result(activate(
        root,
        &cold,
        CURRENT,
        &recipe,
        ImageClass::Bootstrap,
        "",
    ));
    if !outcome.is_ok() {
        return outcome.into_result();
    }
    outcome
        .postcondition(crate::workflow_output::write(&[
            ("current-ready", "true".into()),
            ("build-required", "false".into()),
            ("driver-origin", "built-cold".into()),
        ]))
        .into_result()
}

pub fn build(root: &Path) -> Result<()> {
    let mut budget = crate::segment_cache::OptionalBudget::default();
    let source = budget.run(|| {
        Ok(crate::segment_cache::SourceSession::begin(
            root,
            crate::download_cache::DownloadFamily::Workspace,
        ))
    })?;
    if source.blocks_work() {
        return source.finish(
            root,
            &crate::work_outcome::WorkOutcome::observed(
                Ok(()),
                crate::work_outcome::WriterSettlement::NotStarted,
            ),
        );
    }
    let mut source_writers = crate::work_outcome::WriterSettlement::NotStarted;
    let outcome = crate::work_outcome::WorkOutcome::from_result(build_owned(
        root,
        &mut source_writers,
        &mut budget,
    ));
    finish_with_source(outcome, source_writers, |owner| {
        optional(&mut budget, || source.finish(root, owner)).map(|_| ())
    })
}

fn finish_with_source(
    outcome: crate::work_outcome::WorkOutcome<()>,
    writers: crate::work_outcome::WriterSettlement,
    finish: impl FnOnce(&crate::work_outcome::WorkOutcome<()>) -> Result<()>,
) -> Result<()> {
    let source = crate::work_outcome::WorkOutcome::observed(Ok(()), writers);
    let retention = finish(&source);
    outcome.post_finalization(retention).into_result()
}

fn build_owned(
    root: &Path,
    source_writers: &mut crate::work_outcome::WriterSettlement,
    budget: &mut crate::segment_cache::OptionalBudget,
) -> Result<()> {
    unavailable()?;
    let recipe = read_recipe(root)?;
    let source_seal = bounded(120, || {
        crate::cache_inputs::local_files(root, "ci-driver-build")
    })?;
    let before = optional(budget, || {
        for kind in [
            crate::cache_snapshot::SnapshotKind::RegistryArchives,
            crate::cache_snapshot::SnapshotKind::RegistryIndex,
        ] {
            crate::cache_snapshot::import_source(root, kind)?;
        }
        let before = if reuse_enabled(&recipe) {
            optional_identity(root, &recipe)?
        } else {
            None
        };
        if before.is_some() {
            crate::cache_snapshot::import_transfer(root, compiler_selection())?;
        }
        Ok(before)
    })?
    .flatten();
    if before.is_none() {
        crate::cache_restore::prepare(
            root,
            "ci-driver-build",
            "complete",
            crate::cache_restore::RestoreMode::Discard,
        )?;
    }
    let outcome = managed_compilation(root, &recipe);
    *source_writers = source_writers.join(outcome.writers());
    let writers = outcome.writers();
    let settled = writers.permits_reading();
    let succeeded = outcome.is_ok();
    let mut assembly = crate::work_outcome::WorkSequence::after_settled();
    let mut result = assembly.observe(outcome.map(|_| ()));
    if settled {
        let seal = assembly.observe(crate::work_outcome::WorkOutcome::from_result(bounded(
            120,
            || crate::cache_inputs::local_files(root, "ci-driver-build"),
        )));
        let source_unchanged = seal.as_ref().is_ok_and(|after| after == &source_seal);
        if !source_unchanged {
            secondary(
                &mut result,
                seal.err().unwrap_or_else(|| {
                    error("driver tracked source inputs changed during compilation")
                }),
            );
        }
        let after = optional(budget, || {
            if reuse_enabled(&recipe) {
                optional_identity(root, &recipe)
            } else {
                Ok(None)
            }
        })
        .map(Option::flatten);
        match after {
            Ok(after) => {
                let unchanged = matches!((&before, &after), (Some(before), Some(after)) if before.key == after.key && before.recipe == after.recipe);
                let changed = matches!((&before,&after),(Some(before),Some(after)) if before.key != after.key || before.recipe != after.recipe);
                if succeeded && changed {
                    secondary(
                        &mut result,
                        error("driver build inputs changed during compilation"),
                    );
                }
                let from = root
                    .join("target/ci-driver-build")
                    .join(host_name())
                    .join("release");
                let modeled = !succeeded
                    || match optional(budget, || {
                        modeled_depinfo(root, &from.join("memcordon-ci.d"))
                    }) {
                        Ok(modeled) => modeled.unwrap_or(false),
                        Err(error) => {
                            optional_failure(&mut result, error);
                            false
                        }
                    };
                let mut ready = false;
                if succeeded && !changed && source_unchanged {
                    let source = after.as_ref().map_or("", |identity| identity.key.as_str());
                    match bounded(180, || {
                        activate(root, &from, CURRENT, &recipe, ImageClass::Current, source)
                    }) {
                        Ok(()) => {
                            ready = true;
                        }
                        Err(error) => secondary(&mut result, error),
                    }
                    if ready {
                        if unchanged
                            && modeled
                            && let Err(error) = budget.run(|| {
                                offer_image(root, &recipe, &from, ImageClass::Current, source)
                            })
                        {
                            optional_failure(&mut result, error);
                        }
                        if let Err(error) = budget
                            .run(|| offer_image(root, &recipe, &from, ImageClass::Bootstrap, ""))
                        {
                            optional_failure(&mut result, error);
                        }
                    }
                }
                // Invalid executables can still leave a useful partial target.
                let decision = crate::segment_cache::compilation_retention(
                    trusted_write(),
                    unchanged,
                    modeled,
                    writers,
                    succeeded && ready,
                );
                if decision != crate::segment_cache::RetentionDecision::None {
                    let complete = decision == crate::segment_cache::RetentionDecision::Complete;
                    match budget.run(|| {
                        crate::cache_snapshot::stage_transfer(root, compiler_selection(), complete)
                    }) {
                        Ok(transfer) => {
                            let output = (|| {
                                crate::workflow_output::write(&[
                                    (
                                        if complete {
                                            "compiled-complete-key"
                                        } else {
                                            "compiled-partial-key"
                                        },
                                        transfer.key,
                                    ),
                                    (
                                        if complete {
                                            "compiled-complete-path"
                                        } else {
                                            "compiled-partial-path"
                                        },
                                        crate::workflow_output::action_path(&transfer.path)?,
                                    ),
                                    (
                                        if complete {
                                            "compiled-complete-save"
                                        } else {
                                            "compiled-partial-save"
                                        },
                                        "true".into(),
                                    ),
                                ])
                            })();
                            if let Err(error) = output {
                                eprintln!("driver compiler output emission failed: {error}");
                            }
                        }
                        Err(error) => optional_failure(&mut result, error),
                    }
                }
                if ready
                    && let Err(error) = crate::workflow_output::write(&[
                        ("current-ready", "true".into()),
                        ("build-required", "false".into()),
                        ("driver-origin", "built-managed".into()),
                    ])
                {
                    secondary(&mut result, error);
                }
            }
            Err(error) => {
                result = match result {
                    Ok(()) => Err(error),
                    Err(primary) => Err(CiError::LaneFailures {
                        primary: Box::new(primary),
                        secondary: Box::new(error),
                    }),
                };
            }
        }
    }
    assembly.finish(result)
}

fn managed_compilation(root: &Path, recipe: &Recipe) -> crate::work_outcome::WorkOutcome<Vec<u8>> {
    CommandSpec::cargo(
        "rustup",
        root,
        &recipe.toolchain,
        Duration::from_secs(30 * 60),
    )
    .args([
        "build",
        "--locked",
        "--release",
        "--target-dir",
        "target/ci-driver-build",
        "-p",
        "memcordon-ci",
        "--bin",
        "memcordon-ci",
    ])
    .args(["--target", host_name()])
    .bootstrap_environment()
    .run_owned()
}

/// Remove only declared transfer/inbox paths after their provider actions.
/// Active runtime and cold compiler roots deliberately never enter this set.
pub fn cleanup(root: &Path) -> Result<()> {
    bounded(120, || {
        let mut result = Ok(());
        for relative in [IMAGE_IN, IMAGE_OUT, BOOTSTRAP_OUT, CANDIDATE] {
            let removed = (|| -> Result<()> {
                budget_check()?;
                let path = crate::cache_restore::safe_root(root, Path::new(relative))
                    .map_err(|error| CiError::CacheSafety(Box::new(error)))?;
                if path.try_exists()? {
                    std::fs::remove_dir_all(path)?;
                }
                Ok(())
            })();
            if let Err(error) = removed {
                secondary(&mut result, error);
            }
        }
        for removed in [
            crate::cache_snapshot::cleanup_transfers(root, compiler_selection()),
            crate::cache_snapshot::cleanup_source(root),
        ] {
            if let Err(error) = removed {
                secondary(&mut result, error);
            }
        }
        result
    })
}

#[cfg(test)]
#[path = "../tests/private/driver_cache.rs"]
mod tests;
