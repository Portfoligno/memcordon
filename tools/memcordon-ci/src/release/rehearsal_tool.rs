//! A separate CI-only helper archive; the original publisher archive stays unchanged.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Cursor,
    path::Path,
};

use crate::{CiError, Result};

use super::{artifacts, target};

pub const EXECUTABLE: &str = "memcordon-release-rehearsal";
pub const ARCHIVE: &str = "memcordon-release-rehearsal.tar.gz";
const TARGET: &str = "x86_64-unknown-linux-gnu";

/// Package the freshly built sibling without rebuilding or modifying source.
pub fn package(root: &Path) -> Result<()> {
    let publisher = std::env::current_exe()?;
    let sibling = publisher
        .parent()
        .ok_or_else(|| CiError::Message("CI executable has no parent".into()))?
        .join(EXECUTABLE);
    package_file(&sibling, &root.join(".release/rehearsal-tool"))
}

/// The explicit path seam also permits archive-contract tests without a build.
pub fn package_file(image: &Path, destination: &Path) -> Result<()> {
    if destination.try_exists()? {
        return Err(CiError::Message(
            "rehearsal helper output must be fresh".into(),
        ));
    }
    let image = artifacts::read_file(image)?;
    target::validate_executable(&image, TARGET)?;
    let archive = target::encode_archive(
        TARGET,
        &BTreeMap::from([(EXECUTABLE.into(), image)]),
        &BTreeSet::from([EXECUTABLE.into()]),
    )?;
    validate_archive(&archive)?;
    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::create_dir(destination)?;
    fs::write(destination.join(ARCHIVE), archive)?;
    Ok(())
}

/// Reject ambiguous executable archives before accepting their inventory.
pub fn validate_archive(bytes: &[u8]) -> Result<()> {
    let members = target::decode_archive(bytes, TARGET)?;
    let image = members
        .get(EXECUTABLE)
        .filter(|_| members.len() == 1)
        .ok_or_else(|| {
            CiError::Message("rehearsal archive needs only its helper executable".into())
        })?;
    target::validate_executable(image, TARGET)?;
    let mut archive = tar::Archive::new(flate2::bufread::GzDecoder::new(Cursor::new(bytes)));
    for entry in archive.entries()? {
        let entry = entry?;
        if entry.header().mode()? != 0o755 {
            return Err(CiError::Message("rehearsal executable mode differs".into()));
        }
    }
    Ok(())
}
