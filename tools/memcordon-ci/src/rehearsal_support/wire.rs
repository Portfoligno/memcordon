//! Cargo upload oracle: decode received framing and compare received normalized TOML.
//! This intentionally does not call the publisher's registry serializer.
use crate::{CiError, Result};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    path::Path,
};

fn invalid(message: &str) -> CiError {
    CiError::Message(message.into())
}
fn word(reader: &mut impl Read) -> Result<u64> {
    let mut bytes = [0_u8; std::mem::size_of::<u32>()];
    reader.read_exact(&mut bytes)?;
    Ok(u64::from(u32::from_le_bytes(bytes)))
}
pub struct DecodedUpload {
    pub name: String,
    pub version: String,
    pub sha256: String,
    pub archive_len: u64,
    pub index: Value,
}

pub fn decode_upload(received: &Path, archive: &Path, maximum: u64) -> Result<DecodedUpload> {
    let mut input = File::open(received)?;
    let metadata_len = word(&mut input)?;
    if metadata_len > 4 * 1024 * 1024 {
        return Err(invalid("fixture Cargo metadata bound exceeded"));
    }
    let mut metadata =
        vec![0; usize::try_from(metadata_len).map_err(|_| invalid("metadata length overflow"))?];
    input.read_exact(&mut metadata)?;
    memcordon_core::canonical_json::reject_duplicate_json_keys(&metadata)
        .map_err(CiError::Message)?;
    let metadata: Value = serde_json::from_slice(&metadata)?;
    let archive_len = word(&mut input)?;
    if archive_len == 0 || archive_len > maximum {
        return Err(invalid("fixture Cargo archive bound exceeded"));
    }
    // Shift in place for the server: the writer trails the reader and cannot
    // overwrite unread bytes. One incomplete archive plus metadata is retained.
    let mut output = if received == archive {
        File::options().write(true).open(archive)?
    } else {
        File::options().write(true).create_new(true).open(archive)?
    };
    let mut left = archive_len;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    while left > 0 {
        let size = usize::try_from(left.min(buffer.len() as u64))
            .map_err(|_| invalid("archive length overflow"))?;
        input.read_exact(&mut buffer[..size])?;
        output.write_all(&buffer[..size])?;
        digest.update(&buffer[..size]);
        left -= size as u64;
    }
    if input.read(&mut [0_u8; 1])? != 0 {
        return Err(invalid("fixture Cargo upload has trailing bytes"));
    }
    output.set_len(archive_len)?;
    output.flush()?;
    output.sync_all()?;
    let sha256 = hex::encode(digest.finalize());
    let name = string(&metadata, "name")?.to_owned();
    let version = string(&metadata, "vers")?.to_owned();
    let readme = metadata.get("readme_file").and_then(Value::as_str);
    let members = normalized_members(archive, &name, &version, readme)?;
    let manifest = members
        .get("Cargo.toml")
        .ok_or_else(|| invalid("received normalized manifest missing"))?;
    let manifest: toml::Table = toml::from_str(
        std::str::from_utf8(manifest).map_err(|_| invalid("received manifest is not UTF-8"))?,
    )?;
    validate_metadata(&metadata, &manifest, &members, &name, &version)?;
    let dependencies = metadata["deps"]
        .as_array()
        .ok_or_else(|| invalid("received upload dependencies missing"))?;
    let deps:Vec<Value>=dependencies.iter().map(|dep|json!({
        "name":dep["explicit_name_in_toml"].as_str().unwrap_or(dep["name"].as_str().expect("validated dependency name")),
        "req":dep["version_req"],"features":dep["features"],"optional":dep["optional"],
        "default_features":dep["default_features"],"target":dep["target"],"kind":dep["kind"],
        "registry":dep["registry"],"package":if dep["explicit_name_in_toml"].is_null(){Value::Null}else{dep["name"].clone()}
    })).collect();
    let mut features = serde_json::Map::new();
    let mut features2 = serde_json::Map::new();
    for (name, values) in metadata["features"]
        .as_object()
        .ok_or_else(|| invalid("received features missing"))?
    {
        let extended = values
            .as_array()
            .ok_or_else(|| invalid("received feature array malformed"))?
            .iter()
            .any(|value| {
                value
                    .as_str()
                    .is_some_and(|value| value.starts_with("dep:") || value.contains("?/"))
            });
        if extended {
            features2.insert(name.clone(), values.clone());
        } else {
            features.insert(name.clone(), values.clone());
        }
    }
    let index = json!({"name":name,"vers":version,"deps":deps,"features":features,"features2":features2,"cksum":sha256,"yanked":false,"links":metadata["links"],"rust_version":metadata["rust_version"],"v":2});
    Ok(DecodedUpload {
        name,
        version,
        sha256,
        archive_len,
        index,
    })
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| invalid("received metadata string missing"))
}
fn normalized_members(
    path: &Path,
    name: &str,
    version: &str,
    readme: Option<&str>,
) -> Result<BTreeMap<String, Vec<u8>>> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
        || semver::Version::parse(version).is_err()
    {
        return Err(invalid("received package identity invalid"));
    }
    let prefix = format!("{name}-{version}");
    let decoder = flate2::read::GzDecoder::new(File::open(path)?);
    let mut archive = tar::Archive::new(decoder);
    let mut result = BTreeMap::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut total = 0_u64;
    for entry in archive.entries()? {
        let mut entry = entry?;
        let full = entry.path()?.into_owned();
        let relative = full
            .strip_prefix(&prefix)
            .map_err(|_| invalid("received crate root differs"))?;
        if relative.as_os_str().is_empty() && entry.header().entry_type().is_dir() {
            continue;
        }
        if !entry.header().entry_type().is_file()
            || relative
                .components()
                .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(invalid("received crate entry unsafe"));
        }
        total = total
            .checked_add(entry.size())
            .ok_or_else(|| invalid("received crate size overflow"))?;
        if total > 256 * 1024 * 1024 || entry.size() > 32 * 1024 * 1024 {
            return Err(invalid("received crate expanded size bound"));
        }
        let key = relative
            .to_str()
            .ok_or_else(|| invalid("received crate path not UTF-8"))?
            .to_owned();
        // The oracle retains metadata files only; archives themselves remain file-backed.
        if !seen.insert(key.clone()) {
            return Err(invalid("received crate duplicate entry"));
        }
        if key == "Cargo.toml" || readme == Some(key.as_str()) {
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes)?;
            if result.insert(key, bytes).is_some() {
                return Err(invalid("received crate duplicate metadata entry"));
            }
        }
    }
    Ok(result)
}

fn strings(value: Option<&toml::Value>) -> Result<Value> {
    let Some(value) = value else {
        return Ok(json!([]));
    };
    let array = value
        .as_array()
        .ok_or_else(|| invalid("received manifest array malformed"))?;
    let values: Result<Vec<_>> = array
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or_else(|| invalid("received manifest string malformed"))
        })
        .collect();
    Ok(json!(values?))
}
fn nullable(value: Option<&toml::Value>) -> Result<Value> {
    value.map_or(Ok(Value::Null), |value| {
        value
            .as_str()
            .map(|value| json!(value))
            .ok_or_else(|| invalid("received manifest scalar malformed"))
    })
}
fn validate_metadata(
    metadata: &Value,
    manifest: &toml::Table,
    members: &BTreeMap<String, Vec<u8>>,
    name: &str,
    version: &str,
) -> Result<()> {
    let package = manifest
        .get("package")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| invalid("received package table missing"))?;
    if package.get("name").and_then(toml::Value::as_str) != Some(name)
        || package.get("version").and_then(toml::Value::as_str) != Some(version)
        || package.get("publish").and_then(toml::Value::as_bool) == Some(false)
    {
        return Err(invalid("received upload/archive identity differs"));
    }
    for key in ["authors", "keywords", "categories"] {
        if metadata.get(key) != Some(&strings(package.get(key))?) {
            return Err(invalid("received publication arrays differ"));
        }
    }
    for (source, destination) in [
        ("description", "description"),
        ("documentation", "documentation"),
        ("homepage", "homepage"),
        ("license", "license"),
        ("license-file", "license_file"),
        ("repository", "repository"),
        ("links", "links"),
        ("rust-version", "rust_version"),
    ] {
        if metadata.get(destination) != Some(&nullable(package.get(source))?) {
            return Err(invalid("received publication metadata differs"));
        }
    }
    let features = manifest.get("features").map_or(Ok(json!({})), |value| {
        serde_json::to_value(value).map_err(CiError::from)
    })?;
    if metadata.get("features") != Some(&features) {
        return Err(invalid("received features differ"));
    }
    let badges = manifest.get("badges").map_or(Ok(json!({})), |value| {
        serde_json::to_value(value).map_err(CiError::from)
    })?;
    if metadata.get("badges") != Some(&badges) {
        return Err(invalid("received badges differ"));
    }
    let readme = package
        .get("readme")
        .filter(|value| value.as_bool() != Some(false))
        .map(|value| {
            value
                .as_str()
                .ok_or_else(|| invalid("received readme path malformed"))
        })
        .transpose()?;
    let file = readme.map_or(Value::Null, |path| json!(path));
    let body = readme
        .map(|path| {
            members
                .get(path)
                .ok_or_else(|| invalid("received README missing"))
                .and_then(|bytes| {
                    std::str::from_utf8(bytes)
                        .map(|text| json!(text))
                        .map_err(|_| invalid("received README not UTF-8"))
                })
        })
        .transpose()?
        .unwrap_or(Value::Null);
    if metadata.get("readme_file") != Some(&file) || metadata.get("readme") != Some(&body) {
        return Err(invalid("received README metadata differs"));
    }
    let mut expected = Vec::new();
    manifest_dependencies(manifest, None, &mut expected)?;
    if let Some(targets) = manifest.get("target") {
        for (target, table) in targets
            .as_table()
            .ok_or_else(|| invalid("received target table malformed"))?
        {
            manifest_dependencies(
                table
                    .as_table()
                    .ok_or_else(|| invalid("received target entry malformed"))?,
                Some(target),
                &mut expected,
            )?;
        }
    }
    let mut actual = metadata
        .get("deps")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid("received dependencies missing"))?
        .clone();
    expected.sort_by_cached_key(Value::to_string);
    actual.sort_by_cached_key(Value::to_string);
    if actual != expected {
        return Err(invalid(
            "received dependencies differ from normalized archive",
        ));
    }
    Ok(())
}
fn manifest_dependencies(
    table: &toml::Table,
    target: Option<&str>,
    out: &mut Vec<Value>,
) -> Result<()> {
    for (section, kind) in [
        ("dependencies", "normal"),
        ("dev-dependencies", "dev"),
        ("build-dependencies", "build"),
    ] {
        let Some(section) = table.get(section) else {
            continue;
        };
        for (alias, fields) in section
            .as_table()
            .ok_or_else(|| invalid("received dependency section malformed"))?
        {
            let fields = fields
                .as_table()
                .ok_or_else(|| invalid("received normalized dependency malformed"))?;
            if fields.keys().any(|key| {
                ![
                    "version",
                    "package",
                    "features",
                    "optional",
                    "default-features",
                ]
                .contains(&key.as_str())
            }) {
                return Err(invalid("received dependency source unsupported"));
            }
            let original = fields
                .get("package")
                .and_then(toml::Value::as_str)
                .unwrap_or(alias);
            let requirement = fields
                .get("version")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| invalid("received dependency requirement absent"))?;
            semver::VersionReq::parse(requirement)?;
            let boolean = |key: &str, default: bool| {
                fields.get(key).map_or(Ok(default), |value| {
                    value
                        .as_bool()
                        .ok_or_else(|| invalid("received dependency boolean malformed"))
                })
            };
            out.push(json!({"name":original,"version_req":requirement,"features":strings(fields.get("features"))?,"optional":boolean("optional",false)?,"default_features":boolean("default-features",true)?,"target":target,"kind":kind,"registry":null,"explicit_name_in_toml":if original==alias{None}else{Some(alias)}}));
        }
    }
    Ok(())
}
