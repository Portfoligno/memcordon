use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

fn packaged_commit(manifest: &Path) -> Option<String> {
    let bytes = fs::read(manifest.join(".cargo_vcs_info.json")).ok()?;
    let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    value
        .get("git")?
        .get("sha1")?
        .as_str()
        .filter(|commit| valid_commit(commit))
        .map(str::to_owned)
}

fn git_directory(manifest: &Path) -> Option<PathBuf> {
    for ancestor in manifest.ancestors() {
        let candidate = ancestor.join(".git");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if candidate.is_file() {
            let value = fs::read_to_string(&candidate).ok()?;
            let relative = value.trim().strip_prefix("gitdir: ")?;
            return Some(ancestor.join(relative));
        }
    }
    None
}

fn workspace_commit(manifest: &Path) -> Option<String> {
    let git = git_directory(manifest)?;
    let head = fs::read_to_string(git.join("HEAD")).ok()?;
    let head = head.trim();
    if valid_commit(head) {
        return Some(head.to_owned());
    }
    let reference = head.strip_prefix("ref: ")?;
    if let Ok(value) = fs::read_to_string(git.join(reference)) {
        let commit = value.trim();
        if valid_commit(commit) {
            return Some(commit.to_owned());
        }
    }
    let packed = fs::read_to_string(git.join("packed-refs")).ok()?;
    packed.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let commit = fields.next()?;
        let name = fields.next()?;
        (name == reference && valid_commit(commit)).then(|| commit.to_owned())
    })
}

fn valid_commit(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn watch_git_identity(manifest: &Path) {
    let Some(git) = git_directory(manifest) else {
        return;
    };
    let head_path = git.join("HEAD");
    println!("cargo:rerun-if-changed={}", head_path.display());
    if let Ok(head) = fs::read_to_string(&head_path)
        && let Some(reference) = head.trim().strip_prefix("ref: ")
    {
        println!("cargo:rerun-if-changed={}", git.join(reference).display());
        println!(
            "cargo:rerun-if-changed={}",
            git.join("packed-refs").display()
        );
    }
}

fn main() {
    let manifest = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let output = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("source_commit.rs");
    let commit = packaged_commit(&manifest)
        .or_else(|| workspace_commit(&manifest))
        .unwrap_or_else(|| "unknown".to_owned());
    let mut file = fs::File::create(output).unwrap();
    writeln!(file, "pub const SOURCE_COMMIT: &str = {commit:?};").unwrap();
    println!("cargo:rerun-if-changed=.cargo_vcs_info.json");
    watch_git_identity(&manifest);
}
