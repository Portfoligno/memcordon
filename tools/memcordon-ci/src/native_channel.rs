use std::path::Path;

use crate::{CiError, Result};

#[derive(Clone, Copy, Debug, Eq, PartialEq, clap::ValueEnum)]
pub enum NativeChannelRequirement {
    RequiredDownloadedArchive,
    DevelopmentSourceAllowed,
}

impl NativeChannelRequirement {
    pub fn validate_input(self, input: &Path) -> Result<()> {
        if self == Self::RequiredDownloadedArchive && !input.is_dir() {
            return Err(CiError::Message("release Windows qualification requires its downloaded native archive; development source fallback is forbidden".into()));
        }
        Ok(())
    }
}
