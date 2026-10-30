//! Actual current Linux private product preparation and installed execution.
use super::{
    distribution::{self, TargetDistribution},
    installed_consumer,
    source::BuildSourceIdentity,
    target,
};
use crate::{CiError, Result};
use std::{fs, path::Path};

fn selected(root: &Path) -> Result<TargetDistribution> {
    let native = distribution::native_target()?;
    if !matches!(
        native,
        "x86_64-unknown-linux-gnu" | "aarch64-unknown-linux-gnu"
    ) {
        return Err(CiError::Message(
            "current private suite requires its native Linux target".into(),
        ));
    }
    distribution::Distribution::read(root)?
        .with_runtime_components()?
        .targets
        .into_iter()
        .find(|selection| selection.target == native)
        .ok_or_else(|| CiError::Message("current native Linux distribution absent".into()))
}

pub fn prepare_working(root: &Path, destination: &Path) -> Result<()> {
    let selection = selected(root)?;
    let source = BuildSourceIdentity::working(root)?;
    target::build_selected(root, &source, &selection, destination)?;
    source.recheck(root)
}

pub fn run_prepared(root: &Path, prepared: &Path, destination: &Path) -> Result<()> {
    let (bundle, _) = target::TargetBundle::load(prepared)?;
    if !matches!(bundle.source, BuildSourceIdentity::Working { .. })
        || bundle.distribution != selected(root)?
    {
        return Err(CiError::Message(
            "prepared current Linux product selection differs".into(),
        ));
    }
    fs::create_dir(destination)?;
    let payload = installed_consumer::materialize_native(prepared, destination)?;
    installed_consumer::run_materialized_channel(root, &payload, &destination.join("installed"))
}

pub fn run_working(root: &Path, destination: &Path) -> Result<()> {
    fs::create_dir(destination)?;
    let prepared = destination.join("prepared");
    prepare_working(root, &prepared)?;
    run_prepared(root, &prepared, &destination.join("native"))
}
