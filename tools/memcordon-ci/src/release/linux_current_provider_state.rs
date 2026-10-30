//! Own only the exact current descriptor inodes used by provider negatives.
use crate::{CiError, Result};
use std::{
    fs::{self, File},
    io::{Read, Write},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
};
const NAME: &str = "memcordon-runtime-manifest.json";
const PARENT: &str = "/usr/libexec";
fn held(parent: &File, name: &str) -> Result<Option<File>> {
    match rustix::fs::openat(
        parent,
        name,
        rustix::fs::OFlags::RDONLY | rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    ) {
        Ok(file) => Ok(Some(File::from(file))),
        Err(rustix::io::Errno::NOENT) => Ok(None),
        Err(error) => Err(std::io::Error::from(error).into()),
    }
}
fn identity(file: &File) -> Result<serde_json::Value> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.len() > 4 * 1024 * 1024
    {
        return Err(CiError::Message(
            "current descriptor fixture native custody differs".into(),
        ));
    }
    Ok(
        serde_json::json!({"device":metadata.dev(),"inode":metadata.ino(),"mode":metadata.mode(),"uid":metadata.uid()}),
    )
}
fn same(file: &File, expected: &serde_json::Value) -> Result<bool> {
    Ok(identity(file)? == *expected)
}
fn bytes(file: &File) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    file.take(4 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 4 * 1024 * 1024 {
        return Err(CiError::Message(
            "current descriptor fixture exceeds bound".into(),
        ));
    }
    Ok(bytes)
}
fn parent() -> Result<File> {
    let parent = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(PARENT)?;
    let metadata = parent.metadata()?;
    if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(CiError::Message(
            "current descriptor parent is not protected".into(),
        ));
    }
    Ok(parent)
}

pub fn begin(
    owner: &mut serde_json::Value,
    lifetime: &Path,
    scenario: &str,
) -> Result<serde_json::Value> {
    if owner["provider_fixture"].is_object() && owner["provider_fixture"]["restored"] != true {
        return Err(CiError::Message(
            "prior current descriptor fixture remains unsettled".into(),
        ));
    }
    let parent = parent()?;
    let original = held(&parent, NAME)?
        .ok_or_else(|| CiError::Message("current installed descriptor absent".into()))?;
    let original_identity = identity(&original)?;
    let original_bytes = bytes(&original)?;
    memcordon_core::runtime_manifest_v2::RuntimeManifestV2::parse(&original_bytes)
        .map_err(CiError::Message)?;
    let mut malformed: serde_json::Value = serde_json::from_slice(&original_bytes)?;
    match scenario {
        "unsupported-provider-version" => malformed["revision"] = 255.into(),
        "corrupted-binding" => {
            let components = malformed["components"]
                .as_array_mut()
                .ok_or_else(|| CiError::Message("current component inventory absent".into()))?;
            let agent = components
                .iter_mut()
                .find(|component| component["role"] == "sealed-agent")
                .ok_or_else(|| CiError::Message("current provider component absent".into()))?;
            agent["sha256"] = "0".repeat(64).into();
        }
        _ => return Err(CiError::Message("unknown current provider negative".into())),
    }
    let bad_bytes = serde_json::to_vec(&malformed)?;
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(|error| CiError::Message(error.to_string()))?;
    let backup = format!(".memcordon-negative-original-{}", hex::encode(nonce));
    let stage = format!(".memcordon-negative-current-{}", hex::encode(nonce));
    owner["provider_fixture"] = serde_json::json!({"scenario":scenario,"original":original_identity,"original_sha256":super::artifacts::checksum(&original_bytes),"backup":backup,"stage":stage,"bad":null,"bad_sha256":super::artifacts::checksum(&bad_bytes),"restored":false});
    super::source::write_json(&lifetime.join("current-owner.json"), owner)?;
    // An anonymous current fixture inode cannot leave an unrecorded named
    // object if the controller dies between creation and durable intent.
    let mut file = File::from(
        rustix::fs::openat(
            &parent,
            ".",
            rustix::fs::OFlags::RDWR | rustix::fs::OFlags::TMPFILE | rustix::fs::OFlags::CLOEXEC,
            rustix::fs::Mode::from_raw_mode(0o444),
        )
        .map_err(std::io::Error::from)?,
    );
    owner["provider_fixture"]["bad"] = identity(&file)?;
    super::source::write_json(&lifetime.join("current-owner.json"), owner)?;
    file.write_all(&bad_bytes)?;
    file.sync_all()?;
    rustix::fs::linkat(
        &file,
        "",
        &parent,
        stage.as_str(),
        rustix::fs::AtFlags::EMPTY_PATH,
    )
    .map_err(std::io::Error::from)?;
    let named = held(&parent, NAME)?.ok_or_else(|| {
        CiError::Message("current descriptor disappeared before owned fixture".into())
    })?;
    if !same(&named, &owner["provider_fixture"]["original"])? {
        return Err(CiError::Message(
            "current descriptor changed before fixture publication".into(),
        ));
    }
    rustix::fs::linkat(
        &parent,
        NAME,
        &parent,
        backup.as_str(),
        rustix::fs::AtFlags::empty(),
    )
    .map_err(std::io::Error::from)?;
    rustix::fs::renameat(&parent, stage.as_str(), &parent, NAME).map_err(std::io::Error::from)?;
    parent.sync_all()?;
    Ok(
        serde_json::json!({"format":"memcordon.linux-current-provider-fixture","revision":1,"scenario":scenario,"original":owner["provider_fixture"]["original"],"bad":owner["provider_fixture"]["bad"],"original_bytes":original_bytes,"bad_bytes":bad_bytes}),
    )
}

pub fn restore(owner: &mut serde_json::Value, lifetime: &Path) -> Result<()> {
    let fixture = &owner["provider_fixture"];
    if fixture.is_null() || fixture["restored"] == true {
        return Ok(());
    }
    let parent = parent()?;
    let role = |field: &str, prefix: &str| -> Result<String> {
        let value = fixture[field]
            .as_str()
            .ok_or_else(|| CiError::Message("descriptor fixture finite role absent".into()))?;
        if !value.starts_with(prefix)
            || value.len() != prefix.len() + 32
            || !value[prefix.len()..]
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(CiError::Message(
                "descriptor fixture path is not original finite role".into(),
            ));
        }
        Ok(value.into())
    };
    let backup = role("backup", ".memcordon-negative-original-")?;
    let stage = role("stage", ".memcordon-negative-current-")?;
    let named = held(&parent, NAME)?;
    let saved = held(&parent, &backup)?;
    let original_named = named
        .as_ref()
        .map(|file| same(file, &fixture["original"]))
        .transpose()?
        .unwrap_or(false);
    if original_named {
        if super::artifacts::checksum(&bytes(named.as_ref().expect("actual named inode"))?)
            != fixture["original_sha256"]
        {
            return Err(CiError::Message(
                "original descriptor bytes changed; retained".into(),
            ));
        }
        if let Some(saved) = saved {
            if !same(&saved, &fixture["original"])? {
                return Err(CiError::Message(
                    "descriptor fixture backup replaced; retained".into(),
                ));
            }
            rustix::fs::unlinkat(&parent, backup.as_str(), rustix::fs::AtFlags::empty())
                .map_err(std::io::Error::from)?;
        }
    } else {
        let saved = saved.ok_or_else(|| {
            CiError::Message("original current descriptor backup absent; retained".into())
        })?;
        if !same(&saved, &fixture["original"])?
            || super::artifacts::checksum(&bytes(&saved)?) != fixture["original_sha256"]
        {
            return Err(CiError::Message(
                "original descriptor backup custody differs; retained".into(),
            ));
        }
        if let Some(named) = named
            && (fixture["bad"].is_null() || !same(&named, &fixture["bad"])?)
        {
            return Err(CiError::Message(
                "occupied descriptor is not owned fixture; retained".into(),
            ));
        }
        rustix::fs::renameat(&parent, backup.as_str(), &parent, NAME)
            .map_err(std::io::Error::from)?;
    }
    if let Some(staged) = held(&parent, &stage)? {
        if fixture["bad"].is_null() || !same(&staged, &fixture["bad"])? {
            return Err(CiError::Message(
                "descriptor staging fixture replaced; retained".into(),
            ));
        }
        rustix::fs::unlinkat(&parent, stage.as_str(), rustix::fs::AtFlags::empty())
            .map_err(std::io::Error::from)?;
    }
    parent.sync_all()?;
    let restored = held(&parent, NAME)?
        .ok_or_else(|| CiError::Message("restored current descriptor absent".into()))?;
    if !same(&restored, &fixture["original"])? {
        return Err(CiError::Message(
            "current descriptor native restoration differs".into(),
        ));
    }
    owner["provider_fixture"]["restored"] = true.into();
    super::source::write_json(&lifetime.join("current-owner.json"), owner)
}
