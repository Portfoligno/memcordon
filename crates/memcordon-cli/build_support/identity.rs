//! Pure identity selection. Inherited environment commit strings are not inputs.
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Packaged {
    git: PackageGit,
    #[serde(rename = "path_in_vcs")]
    _path_in_vcs: Option<String>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageGit {
    sha1: String,
    #[serde(rename = "dirty")]
    _dirty: Option<bool>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Released {
    schema: u32,
    source_commit: String,
}

const GIT_SHA1_BYTES: usize = 20;
const GIT_SHA256_BYTES: usize = 32;

pub fn valid_commit(value: &str) -> bool {
    [GIT_SHA1_BYTES, GIT_SHA256_BYTES]
        .into_iter()
        .any(|bytes| value.len() == bytes * 2)
        && value.bytes().all(|byte| byte.is_ascii_hexdigit())
        && value.bytes().any(|byte| byte != b'0')
}

pub fn packaged_commit(bytes: &[u8]) -> Result<String, String> {
    let value: Packaged = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    valid_commit(&value.git.sha1)
        .then_some(value.git.sha1)
        .ok_or_else(|| "Cargo metadata lacks an exact source commit".into())
}

pub fn release_commit(bytes: &[u8]) -> Result<String, String> {
    let value: Released = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
    if value.schema != 1 {
        return Err("unsupported release source metadata schema".into());
    }
    valid_commit(&value.source_commit)
        .then_some(value.source_commit)
        .ok_or_else(|| "release metadata lacks an exact source commit".into())
}

/// HEAD remains its exact commit when files are dirty. This is not a clean-tree
/// attestation; release preflight separately rejects dirty worktrees and indexes.
pub fn select(
    packaged: Option<&[u8]>,
    checkout: Option<&str>,
    release: Option<&[u8]>,
) -> Result<String, String> {
    if let Some(packaged) = packaged {
        return packaged_commit(packaged);
    }
    if let Some(checkout) = checkout {
        return valid_commit(checkout)
            .then(|| checkout.to_owned())
            .ok_or_else(|| "checkout identity is not an exact commit".into());
    }
    if let Some(release) = release {
        return release_commit(release);
    }
    Ok("unknown".into())
}

pub fn reference(head: &str) -> Option<&str> {
    let reference = head.trim().strip_prefix("ref: ")?;
    (reference.starts_with("refs/")
        && reference
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && !part.contains('\\')))
    .then_some(reference)
}

pub fn resolve_head(
    head: &str,
    loose: &[Option<String>],
    packed: &[Option<String>],
) -> Result<Option<String>, String> {
    let head = head.trim();
    if valid_commit(head) {
        return Ok(Some(head.to_owned()));
    }
    let reference = reference(head).ok_or("invalid Git HEAD identity")?;
    if let Some(value) = loose.iter().flatten().next() {
        if valid_commit(value.trim()) {
            return Ok(Some(value.trim().to_owned()));
        }
        return Err("invalid loose Git ref must not fall back to stale packed refs".into());
    }
    for contents in packed.iter().flatten() {
        let mut found = None;
        for line in contents.lines() {
            let mut fields = line.split_whitespace();
            match (fields.next(), fields.next(), fields.next()) {
                (Some(commit), Some(name), trailing) if name == reference => {
                    if trailing.is_some() || !valid_commit(commit) || found.is_some() {
                        return Err("invalid or duplicate matching packed Git ref".into());
                    }
                    found = Some(commit.to_owned());
                }
                _ => {}
            }
        }
        if found.is_some() {
            return Ok(found);
        }
    }
    Ok(None)
}
