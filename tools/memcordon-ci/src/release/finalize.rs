//! Inexpensive preparation checks and byte-preserving final artifact handoff.
use super::{
    artifacts, bundle,
    distribution::Distribution,
    rehearsal_input::RehearsalInput,
    source::{self, BuildSourceIdentity},
    target,
};
use crate::{CiError, Result};
use std::{fs, io::Write, path::Path};

fn failure(message: &str) -> CiError {
    CiError::Message(message.into())
}

pub fn check_preparation(root: &Path, build_source: &Path, consumer_readiness: bool) -> Result<()> {
    let selected: BuildSourceIdentity = source::read_json(build_source)?;
    selected.recheck(root)?;
    crate::policy::run(root)?;
    let metadata = crate::policy::workspace_metadata(root)?;
    let order = source::public_order(&metadata, selected.version())?;
    let distribution = Distribution::read(root)?;
    let distribution = if consumer_readiness {
        distribution.consumer_readiness()?
    } else {
        distribution
    };
    if distribution.packages != order {
        return Err(failure("preparation public package order differs"));
    }
    match &selected {
        BuildSourceIdentity::Tagged { .. } => {
            bundle::changelog_notes(root, selected.version())?;
        }
        BuildSourceIdentity::Working { .. } => {
            bundle::candidate_notes(root, selected.version())?;
        }
    }
    Ok(())
}

fn safe_ancestors(path: &Path) -> Result<()> {
    for ancestor in path.ancestors().filter(|path| !path.as_os_str().is_empty()) {
        match fs::symlink_metadata(ancestor) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    return Err(failure("finalization path traverses symlink"));
                }
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    if metadata.file_attributes() & 0x400 != 0 {
                        return Err(failure("finalization path traverses reparse point"));
                    }
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(bytes)?;
    Ok(())
}

/// No Cargo/Git invocation: validate the existing input and copy its original bytes.
pub fn finalize_preparation(
    root: &Path,
    build_source: &Path,
    input: &Path,
    publisher_archive: &Path,
    destination: &Path,
) -> Result<()> {
    safe_ancestors(build_source)?;
    safe_ancestors(input)?;
    safe_ancestors(publisher_archive)?;
    safe_ancestors(destination)?;
    if fs::symlink_metadata(destination).is_ok() {
        return Err(failure("final preparation destination must be fresh"));
    }
    let selected: BuildSourceIdentity = source::read_json(build_source)?;
    selected.validate()?;
    let loaded = RehearsalInput::load(input)?;
    let (actual, envelope, metadata, payloads) = match &loaded {
        RehearsalInput::Tagged(bundle) => (
            BuildSourceIdentity::from(bundle.metadata.source.clone()),
            "prepared.json",
            serde_json::to_value(&bundle.metadata)?,
            &bundle.payloads,
        ),
        RehearsalInput::Candidate { metadata, payloads } => (
            metadata.source.clone(),
            "candidate.json",
            serde_json::to_value(metadata)?,
            payloads,
        ),
    };
    if actual != selected {
        return Err(failure("final preparation source differs from selection"));
    }
    let expected_distribution = Distribution::read(root)?.consumer_readiness()?;
    if metadata["distribution"] != serde_json::to_value(&expected_distribution)? {
        return Err(failure(
            "final preparation effective feature distribution differs",
        ));
    }
    match &loaded {
        RehearsalInput::Tagged(bundle) => {
            if bundle.metadata.notes != bundle::changelog_notes(root, selected.version())? {
                return Err(failure("final preparation selected release notes differ"));
            }
        }
        RehearsalInput::Candidate { metadata, .. } => {
            let (selection, notes) = bundle::candidate_notes(root, selected.version())?;
            if metadata.notes_selection != selection || metadata.notes != notes {
                return Err(failure(
                    "final preparation candidate notes disposition differs",
                ));
            }
        }
    }
    let envelope_bytes = artifacts::read_file(&input.join(envelope))?;
    if serde_json::from_slice::<serde_json::Value>(&envelope_bytes)? != metadata {
        return Err(failure(
            "final preparation envelope changed during validation",
        ));
    }
    let publisher = artifacts::read_file(publisher_archive)?;
    let members = target::decode_archive(&publisher, "x86_64-unknown-linux-gnu")?;
    let image = members
        .get("memcordon-ci")
        .filter(|_| members.len() == 1)
        .ok_or_else(|| failure("publication tool archive inventory differs"))?;
    target::validate_executable(image, "x86_64-unknown-linux-gnu")?;
    if let Some(parent) = destination
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(destination)?;
    let payload_directory = destination.join(if loaded.kind() == "candidate" {
        "candidate"
    } else {
        "prepared"
    });
    fs::create_dir(&payload_directory)?;
    write_new(&payload_directory.join(envelope), &envelope_bytes)?;
    for (record, bytes) in loaded.files().iter().zip(payloads) {
        artifacts::check_bytes(record, bytes)?;
        write_new(&payload_directory.join(&record.name), bytes)?;
    }
    let tool_directory = destination.join("tool");
    fs::create_dir(&tool_directory)?;
    let tool_output = tool_directory.join("memcordon-publication-tool.tar.gz");
    write_new(&tool_output, &publisher)?;
    // Reload the copied bundle through the same mandatory native/package validators.
    let copied = RehearsalInput::load(&payload_directory)?;
    if copied.kind() != loaded.kind()
        || copied.commit() != loaded.commit()
        || copied.version() != loaded.version()
        || artifacts::read_file(&payload_directory.join(envelope))? != envelope_bytes
        || artifacts::read_file(&tool_output)? != publisher
    {
        return Err(failure("final preparation copy differs"));
    }
    for record in loaded.files() {
        if artifacts::read_file(&input.join(&record.name))?
            != artifacts::read_file(&payload_directory.join(&record.name))?
        {
            return Err(failure("final preparation input changed during copying"));
        }
    }
    if artifacts::read_file(&input.join(envelope))? != envelope_bytes
        || artifacts::read_file(publisher_archive)? != publisher
    {
        return Err(failure("final preparation original bytes changed"));
    }
    Ok(())
}
