//! Cargo registry upload framing from validated package metadata and archive bytes.
use super::{artifacts, source::PUBLIC_PACKAGES};
use crate::{CiError, Result};
use serde_json::{Value, json};

pub fn render_upload(
    package: &str,
    version: &str,
    archive: &[u8],
    sha256: &str,
) -> Result<Vec<u8>> {
    if !PUBLIC_PACKAGES.contains(&package)
        || artifacts::checksum(archive) != sha256
        || super::source::version(version)?.to_string() != version
    {
        return Err(CiError::Message("registry archive identity differs".into()));
    }
    let files = artifacts::crate_members(archive)?;
    let (actual_package, actual_version) = artifacts::crate_identity(&files)?;
    if actual_package != package || actual_version.to_string() != version {
        return Err(CiError::Message(
            "registry normalized package identity differs".into(),
        ));
    }
    let manifest = files
        .get("Cargo.toml")
        .expect("validated normalized manifest");
    let manifest: toml::Table = toml::from_str(
        std::str::from_utf8(manifest)
            .map_err(|_| CiError::Message("manifest is not UTF-8".into()))?,
    )?;
    let fields = manifest
        .get("package")
        .and_then(toml::Value::as_table)
        .ok_or_else(|| CiError::Message("registry package fields absent".into()))?;
    if fields
        .get("publish")
        .is_some_and(|value| value.as_bool() == Some(false))
    {
        return Err(CiError::Message("package publication is disabled".into()));
    }
    let mut deps = Vec::new();
    dependencies(&manifest, None, &mut deps)?;
    if let Some(targets) = manifest.get("target") {
        for (target, table) in targets
            .as_table()
            .ok_or_else(|| CiError::Message("target dependencies malformed".into()))?
        {
            dependencies(
                table
                    .as_table()
                    .ok_or_else(|| CiError::Message("target table malformed".into()))?,
                Some(target),
                &mut deps,
            )?;
        }
    }
    let mut metadata = json!({"name":package,"vers":version,"deps":deps,"features":{},"badges":{}});
    for field in ["authors", "keywords", "categories"] {
        metadata[field] = strings(fields.get(field))?;
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
        metadata[destination] = nullable_string(fields.get(source))?;
    }
    if let Some(features) = manifest.get("features") {
        for (name, value) in features
            .as_table()
            .ok_or_else(|| CiError::Message("feature table malformed".into()))?
        {
            metadata["features"][name] = strings(Some(value))?;
        }
    }
    if let Some(badges) = manifest.get("badges") {
        for (name, value) in badges
            .as_table()
            .ok_or_else(|| CiError::Message("badges table malformed".into()))?
        {
            let mut badge = serde_json::Map::new();
            for (key, value) in value
                .as_table()
                .ok_or_else(|| CiError::Message("badge fields malformed".into()))?
            {
                badge.insert(key.clone(), nullable_string(Some(value))?);
            }
            metadata["badges"][name] = Value::Object(badge);
        }
    }
    let readme = match fields.get("readme") {
        None => None,
        Some(value) if value.as_bool() == Some(false) => None,
        Some(value) => Some(
            value
                .as_str()
                .ok_or_else(|| CiError::Message("normalized readme path malformed".into()))?,
        ),
    };
    metadata["readme_file"] = readme.map_or(Value::Null, |value| Value::String(value.into()));
    metadata["readme"] = match readme {
        None => Value::Null,
        Some(path) => {
            artifacts::safe_relative(std::path::Path::new(path))?;
            let bytes = files
                .get(path)
                .ok_or_else(|| CiError::Message("packaged README absent".into()))?;
            Value::String(
                std::str::from_utf8(bytes)
                    .map_err(|_| CiError::Message("README is not UTF-8".into()))?
                    .into(),
            )
        }
    };
    let metadata = serde_json::to_vec(&metadata)?;
    if metadata.len() > 4 * 1024 * 1024 {
        return Err(CiError::Message(
            "registry metadata byte bound exceeded".into(),
        ));
    }
    let mut body = Vec::new();
    body.extend(
        u32::try_from(metadata.len())
            .map_err(|_| CiError::Message("registry metadata overflow".into()))?
            .to_le_bytes(),
    );
    body.extend(metadata);
    body.extend(
        u32::try_from(archive.len())
            .map_err(|_| CiError::Message("registry archive overflow".into()))?
            .to_le_bytes(),
    );
    body.extend_from_slice(archive);
    Ok(body)
}

fn nullable_string(value: Option<&toml::Value>) -> Result<Value> {
    value.map_or(Ok(Value::Null), |value| {
        value
            .as_str()
            .map(|value| Value::String(value.into()))
            .ok_or_else(|| CiError::Message("registry metadata string malformed".into()))
    })
}

fn strings(value: Option<&toml::Value>) -> Result<Value> {
    value.map_or(Ok(json!([])), |value| {
        value
            .as_array()
            .ok_or_else(|| CiError::Message("registry string array malformed".into()))?
            .iter()
            .map(|value| nullable_string(Some(value)))
            .collect::<Result<Vec<_>>>()
            .map(Value::Array)
    })
}

fn dependencies(table: &toml::Table, target: Option<&str>, out: &mut Vec<Value>) -> Result<()> {
    for (section, kind) in [
        ("dependencies", "normal"),
        ("dev-dependencies", "dev"),
        ("build-dependencies", "build"),
    ] {
        let Some(section) = table.get(section) else {
            continue;
        };
        for (alias, value) in section
            .as_table()
            .ok_or_else(|| CiError::Message("dependencies table malformed".into()))?
        {
            let fields = value
                .as_table()
                .ok_or_else(|| CiError::Message("normalized dependency fields malformed".into()))?;
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
                return Err(CiError::Message(
                    "dependency retains a nonregistry source or unsupported fields".into(),
                ));
            }
            let req = fields
                .get("version")
                .and_then(toml::Value::as_str)
                .ok_or_else(|| CiError::Message("dependency version absent".into()))?;
            semver::VersionReq::parse(req)?;
            let original = fields
                .get("package")
                .map(|value| {
                    value
                        .as_str()
                        .ok_or_else(|| CiError::Message("dependency rename malformed".into()))
                })
                .transpose()?
                .unwrap_or(alias);
            let boolean = |key: &str, default| -> Result<bool> {
                fields.get(key).map_or(Ok(default), |value| {
                    value
                        .as_bool()
                        .ok_or_else(|| CiError::Message("dependency boolean malformed".into()))
                })
            };
            out.push(json!({"name":original,"version_req":req,"features":strings(fields.get("features"))?,"optional":boolean("optional",false)?,"default_features":boolean("default-features",true)?,"target":target,"kind":kind,"registry":null,"explicit_name_in_toml":if original != alias { Some(alias) } else { None }}));
        }
    }
    Ok(())
}
