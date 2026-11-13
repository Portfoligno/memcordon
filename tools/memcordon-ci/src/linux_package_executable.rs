//! Exact package-source metadata and descriptor access, without arming a gate.

#[derive(Clone, Copy, Debug)]
pub struct MetadataFacts {
    pub regular: bool,
    pub uid: u32,
    pub mode: u32,
    pub links: u64,
    pub length: u64,
    /// Linux F_GETFL access bits after masking with O_ACCMODE.
    pub access_mode: u32,
}

pub fn validate(facts: &MetadataFacts) -> Result<(), String> {
    // Package sources are 0755. Read-only describes the retained O_RDONLY
    // descriptor, not removal of the root owner's filesystem write bit.
    if facts.regular
        && facts.uid == 0
        && facts.mode & 0o777 == 0o755
        && facts.links == 1
        && facts.length != 0
        && facts.access_mode == 0
    {
        Ok(())
    } else {
        Err(format!(
            "current package executable custody differs; regular={} expected=true; uid={} expected=0; mode={:#o} expected=0o755; links={} expected=1; length={} expected_nonempty=true; access_mode={} expected=O_RDONLY(0)",
            facts.regular,
            facts.uid,
            facts.mode & 0o777,
            facts.links,
            facts.length,
            facts.access_mode
        ))
    }
}

#[cfg(target_os = "linux")]
pub fn inspect(file: &std::fs::File) -> crate::Result<std::fs::Metadata> {
    use std::os::unix::fs::MetadataExt;
    let identity = file.metadata().map_err(|error| {
        crate::CiError::from(error).context("current package executable held metadata")
    })?;
    let flags = rustix::fs::fcntl_getfl(file).map_err(|error| {
        crate::CiError::from(std::io::Error::from(error))
            .context("current package executable held descriptor access")
    })?;
    validate(&MetadataFacts {
        regular: identity.is_file(),
        uid: identity.uid(),
        mode: identity.mode(),
        links: identity.nlink(),
        length: identity.len(),
        access_mode: (flags & rustix::fs::OFlags::ACCMODE).bits(),
    })
    .map_err(crate::CiError::Message)?;
    Ok(identity)
}
